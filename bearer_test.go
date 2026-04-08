package idproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/youyo/idproxy/testutil"
)

// --- BearerValidator テスト用ヘルパー ---

// setupBearerValidator はテスト用の BearerValidator を構築する。
// MockIdP の秘密鍵を OAuthConfig.SigningKey に設定し、
// ExternalURL を issuer として使用する。
func setupBearerValidator(t *testing.T) (*BearerValidator, *testMemoryStore, *testutil.MockIdP) {
	t.Helper()

	idp := testutil.NewMockIdP(t)
	st := newTestMemoryStore()

	cfg := Config{
		Providers: []OIDCProvider{
			{
				Issuer:       idp.Issuer(),
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		},
		ExternalURL:  "http://localhost:8080",
		CookieSecret: []byte("test-cookie-secret-32-bytes-long!"),
		Store:        st,
		OAuth: &OAuthConfig{
			SigningKey: idp.PrivateKey(),
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate() failed: %v", err)
	}

	bv, err := NewBearerValidator(cfg, st)
	if err != nil {
		t.Fatalf("NewBearerValidator() failed: %v", err)
	}

	return bv, st, idp
}

// issueTestToken は検証テスト用の JWT を発行するヘルパー。
func issueTestToken(t *testing.T, idp *testutil.MockIdP, issuer, audience, sub, email, name, jti string, exp time.Time) string {
	t.Helper()
	token, err := idp.IssueAccessToken(issuer, audience, sub, email, name, jti, exp)
	if err != nil {
		t.Fatalf("IssueAccessToken() failed: %v", err)
	}
	return token
}

// --- NewBearerValidator テスト ---

func TestNewBearerValidator_Success(t *testing.T) {
	bv, _, _ := setupBearerValidator(t)
	if bv == nil {
		t.Fatal("NewBearerValidator() returned nil")
	}
}

func TestNewBearerValidator_NoOAuthConfig(t *testing.T) {
	idp := testutil.NewMockIdP(t)
	st := newTestMemoryStore()

	cfg := Config{
		Providers: []OIDCProvider{
			{
				Issuer:       idp.Issuer(),
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		},
		ExternalURL:  "http://localhost:8080",
		CookieSecret: []byte("test-cookie-secret-32-bytes-long!"),
		Store:        st,
		// OAuth is nil
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate() failed: %v", err)
	}

	_, err := NewBearerValidator(cfg, st)
	if err == nil {
		t.Fatal("NewBearerValidator() should return error when OAuth config is nil")
	}
}

// --- Validate テスト ---

func TestBearerValidator_Validate_ValidToken(t *testing.T) {
	bv, st, idp := setupBearerValidator(t)
	ctx := context.Background()

	jti := "test-jti-valid"
	email := "user@example.com"
	sub := "sub-123"
	name := "Test User"
	exp := time.Now().Add(time.Hour)

	// Store にアクセストークンを登録（リボケーションチェック用）
	_ = st.SetAccessToken(ctx, jti, &AccessTokenData{
		JTI:       jti,
		Subject:   sub,
		Email:     email,
		ClientID:  "test-client-id",
		IssuedAt:  time.Now(),
		ExpiresAt: exp,
		Revoked:   false,
	}, time.Hour)

	// aud は ExternalURL（リソースサーバー自身）
	token := issueTestToken(t, idp, "http://localhost:8080", "http://localhost:8080", sub, email, name, jti, exp)

	user, err := bv.Validate(ctx, token)
	if err != nil {
		t.Fatalf("Validate() returned error: %v", err)
	}
	if user == nil {
		t.Fatal("Validate() returned nil user")
	}
	if user.Email != email {
		t.Errorf("expected email %q, got %q", email, user.Email)
	}
	if user.Name != name {
		t.Errorf("expected name %q, got %q", name, user.Name)
	}
	if user.Subject != sub {
		t.Errorf("expected subject %q, got %q", sub, user.Subject)
	}
}

func TestBearerValidator_Validate_ExpiredToken(t *testing.T) {
	bv, st, idp := setupBearerValidator(t)
	ctx := context.Background()

	jti := "test-jti-expired"
	exp := time.Now().Add(-time.Hour) // 1時間前に期限切れ

	_ = st.SetAccessToken(ctx, jti, &AccessTokenData{
		JTI:       jti,
		Subject:   "sub-123",
		Email:     "user@example.com",
		IssuedAt:  time.Now().Add(-2 * time.Hour),
		ExpiresAt: exp,
		Revoked:   false,
	}, time.Hour)

	token := issueTestToken(t, idp, "http://localhost:8080", "http://localhost:8080", "sub-123", "user@example.com", "Test", jti, exp)

	_, err := bv.Validate(ctx, token)
	if err == nil {
		t.Fatal("Validate() should return error for expired token")
	}
}

func TestBearerValidator_Validate_WrongIssuer(t *testing.T) {
	bv, st, idp := setupBearerValidator(t)
	ctx := context.Background()

	jti := "test-jti-wrong-iss"
	exp := time.Now().Add(time.Hour)

	_ = st.SetAccessToken(ctx, jti, &AccessTokenData{
		JTI:       jti,
		Subject:   "sub-123",
		Email:     "user@example.com",
		IssuedAt:  time.Now(),
		ExpiresAt: exp,
		Revoked:   false,
	}, time.Hour)

	// issuer が ExternalURL と一致しない
	token := issueTestToken(t, idp, "https://wrong-issuer.example.com", "http://localhost:8080", "sub-123", "user@example.com", "Test", jti, exp)

	_, err := bv.Validate(ctx, token)
	if err == nil {
		t.Fatal("Validate() should return error for wrong issuer")
	}
}

func TestBearerValidator_Validate_WrongAudience(t *testing.T) {
	bv, st, idp := setupBearerValidator(t)
	ctx := context.Background()

	jti := "test-jti-wrong-aud"
	exp := time.Now().Add(time.Hour)

	_ = st.SetAccessToken(ctx, jti, &AccessTokenData{
		JTI:       jti,
		Subject:   "sub-123",
		Email:     "user@example.com",
		IssuedAt:  time.Now(),
		ExpiresAt: exp,
		Revoked:   false,
	}, time.Hour)

	// audience が ExternalURL と不一致
	token := issueTestToken(t, idp, "http://localhost:8080", "https://wrong-audience.example.com", "sub-123", "user@example.com", "Test", jti, exp)

	_, err := bv.Validate(ctx, token)
	if err == nil {
		t.Fatal("Validate() should return error for wrong audience")
	}
}

func TestBearerValidator_Validate_InvalidSignature(t *testing.T) {
	bv, st, _ := setupBearerValidator(t)
	ctx := context.Background()

	jti := "test-jti-bad-sig"
	exp := time.Now().Add(time.Hour)

	_ = st.SetAccessToken(ctx, jti, &AccessTokenData{
		JTI:       jti,
		Subject:   "sub-123",
		Email:     "user@example.com",
		IssuedAt:  time.Now(),
		ExpiresAt: exp,
		Revoked:   false,
	}, time.Hour)

	// 異なる秘密鍵で署名
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	claims := jwt.MapClaims{
		"iss":   "http://localhost:8080",
		"sub":   "sub-123",
		"aud":   jwt.ClaimStrings{"http://localhost:8080"},
		"email": "user@example.com",
		"name":  "Test",
		"jti":   jti,
		"iat":   time.Now().Unix(),
		"exp":   exp.Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tokenStr, err := tok.SignedString(otherKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	_, err = bv.Validate(ctx, tokenStr)
	if err == nil {
		t.Fatal("Validate() should return error for invalid signature")
	}
}

func TestBearerValidator_Validate_MissingEmail(t *testing.T) {
	bv, st, idp := setupBearerValidator(t)
	ctx := context.Background()

	jti := "test-jti-no-email"
	exp := time.Now().Add(time.Hour)

	_ = st.SetAccessToken(ctx, jti, &AccessTokenData{
		JTI:       jti,
		Subject:   "sub-123",
		Email:     "",
		IssuedAt:  time.Now(),
		ExpiresAt: exp,
		Revoked:   false,
	}, time.Hour)

	// email なしの JWT を直接作成
	claims := jwt.MapClaims{
		"iss": "http://localhost:8080",
		"sub": "sub-123",
		"aud": jwt.ClaimStrings{"http://localhost:8080"},
		"jti": jti,
		"iat": time.Now().Unix(),
		"exp": exp.Unix(),
		// email を意図的に省略
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tokenStr, err := tok.SignedString(idp.PrivateKey())
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	_, err = bv.Validate(ctx, tokenStr)
	if err == nil {
		t.Fatal("Validate() should return error when email claim is missing")
	}
}

func TestBearerValidator_Validate_RevokedToken(t *testing.T) {
	bv, st, idp := setupBearerValidator(t)
	ctx := context.Background()

	jti := "test-jti-revoked"
	exp := time.Now().Add(time.Hour)

	// リボーク済みトークンを Store に登録
	_ = st.SetAccessToken(ctx, jti, &AccessTokenData{
		JTI:       jti,
		Subject:   "sub-123",
		Email:     "user@example.com",
		IssuedAt:  time.Now(),
		ExpiresAt: exp,
		Revoked:   true, // リボーク済み
	}, time.Hour)

	token := issueTestToken(t, idp, "http://localhost:8080", "http://localhost:8080", "sub-123", "user@example.com", "Test", jti, exp)

	_, err := bv.Validate(ctx, token)
	if err == nil {
		t.Fatal("Validate() should return error for revoked token")
	}
}

func TestBearerValidator_Validate_TokenNotInStore(t *testing.T) {
	bv, _, idp := setupBearerValidator(t)
	ctx := context.Background()

	jti := "test-jti-not-in-store"
	exp := time.Now().Add(time.Hour)

	// Store にトークンを登録しない（リボケーションチェックで失敗するはず）
	token := issueTestToken(t, idp, "http://localhost:8080", "http://localhost:8080", "sub-123", "user@example.com", "Test", jti, exp)

	_, err := bv.Validate(ctx, token)
	if err == nil {
		t.Fatal("Validate() should return error when token is not in store")
	}
}

func TestBearerValidator_Validate_MissingJTI(t *testing.T) {
	bv, _, idp := setupBearerValidator(t)
	ctx := context.Background()

	exp := time.Now().Add(time.Hour)

	// jti なしの JWT を直接作成
	claims := jwt.MapClaims{
		"iss":   "http://localhost:8080",
		"sub":   "sub-123",
		"aud":   jwt.ClaimStrings{"http://localhost:8080"},
		"email": "user@example.com",
		"iat":   time.Now().Unix(),
		"exp":   exp.Unix(),
		// jti を意図的に省略
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tokenStr, err := tok.SignedString(idp.PrivateKey())
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	_, err = bv.Validate(ctx, tokenStr)
	if err == nil {
		t.Fatal("Validate() should return error when jti claim is missing")
	}
}

func TestBearerValidator_Validate_MalformedToken(t *testing.T) {
	bv, _, _ := setupBearerValidator(t)
	ctx := context.Background()

	_, err := bv.Validate(ctx, "not-a-valid-jwt")
	if err == nil {
		t.Fatal("Validate() should return error for malformed token")
	}
}
