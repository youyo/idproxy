package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/youyo/idproxy"
)

func testSession() *idproxy.Session {
	now := time.Now()
	return &idproxy.Session{
		ID:             "sess-001",
		User:           &idproxy.User{Email: "test@example.com", Name: "Test User", Subject: "sub-001", Issuer: "https://issuer.example.com"},
		ProviderIssuer: "https://issuer.example.com",
		IDToken:        "eyJhbGciOiJSUzI1NiJ9.test",
		CreatedAt:      now,
		ExpiresAt:      now.Add(24 * time.Hour),
	}
}

func TestNewMemoryStore(t *testing.T) {
	ms := NewMemoryStore()
	if ms == nil {
		t.Fatal("NewMemoryStore() returned nil")
	}

	// Store インターフェースを実装していることをコンパイル時に確認
	var _ idproxy.Store = ms
}

func TestMemoryStore_SetGetSession(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	sess := testSession()

	if err := ms.SetSession(ctx, sess.ID, sess, time.Hour); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}

	got, err := ms.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetSession() returned nil")
	}
	if got.ID != sess.ID {
		t.Errorf("ID = %q, want %q", got.ID, sess.ID)
	}
	if got.User == nil || got.User.Email != sess.User.Email {
		t.Errorf("User.Email = %v, want %v", got.User, sess.User)
	}
	if got.ProviderIssuer != sess.ProviderIssuer {
		t.Errorf("ProviderIssuer = %q, want %q", got.ProviderIssuer, sess.ProviderIssuer)
	}
	if got.IDToken != sess.IDToken {
		t.Errorf("IDToken = %q, want %q", got.IDToken, sess.IDToken)
	}
}

func TestMemoryStore_GetSession_NotFound(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()

	got, err := ms.GetSession(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetSession() = %v, want nil", got)
	}
}

func TestMemoryStore_GetSession_Expired(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	sess := testSession()

	// TTL を 0 に設定 → 即座に期限切れ
	if err := ms.SetSession(ctx, sess.ID, sess, 0); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}

	got, err := ms.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetSession() = %v, want nil (expired)", got)
	}
}

func TestMemoryStore_SetSession_Overwrite(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()

	sess1 := testSession()
	sess2 := testSession()
	sess2.IDToken = "updated-token"

	if err := ms.SetSession(ctx, sess1.ID, sess1, time.Hour); err != nil {
		t.Fatalf("SetSession(1) error = %v", err)
	}
	if err := ms.SetSession(ctx, sess1.ID, sess2, time.Hour); err != nil {
		t.Fatalf("SetSession(2) error = %v", err)
	}

	got, err := ms.GetSession(ctx, sess1.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetSession() returned nil")
	}
	if got.IDToken != "updated-token" {
		t.Errorf("IDToken = %q, want %q", got.IDToken, "updated-token")
	}
}

func TestMemoryStore_DeleteSession(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	sess := testSession()

	if err := ms.SetSession(ctx, sess.ID, sess, time.Hour); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}
	if err := ms.DeleteSession(ctx, sess.ID); err != nil {
		t.Fatalf("DeleteSession() error = %v", err)
	}

	got, err := ms.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetSession() = %v, want nil (deleted)", got)
	}
}

func TestMemoryStore_DeleteSession_NotFound(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()

	if err := ms.DeleteSession(ctx, "nonexistent"); err != nil {
		t.Errorf("DeleteSession() error = %v, want nil", err)
	}
}

func TestMemoryStore_SetSession_ContextCanceled(t *testing.T) {
	ms := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sess := testSession()

	err := ms.SetSession(ctx, sess.ID, sess, time.Hour)
	if err != context.Canceled {
		t.Errorf("SetSession() error = %v, want %v", err, context.Canceled)
	}
}

func TestMemoryStore_GetSession_ContextCanceled(t *testing.T) {
	ms := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := ms.GetSession(ctx, "any")
	if err != context.Canceled {
		t.Errorf("GetSession() error = %v, want %v", err, context.Canceled)
	}
	if got != nil {
		t.Errorf("GetSession() = %v, want nil", got)
	}
}

func TestMemoryStore_DeleteSession_ContextCanceled(t *testing.T) {
	ms := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := ms.DeleteSession(ctx, "any")
	if err != context.Canceled {
		t.Errorf("DeleteSession() error = %v, want %v", err, context.Canceled)
	}
}

func TestMemoryStore_Concurrent(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	for i := range goroutines {
		id := "sess-" + string(rune('A'+i%26))
		sess := &idproxy.Session{
			ID:   id,
			User: &idproxy.User{Email: id + "@example.com"},
		}

		// Set
		go func() {
			defer wg.Done()
			_ = ms.SetSession(ctx, id, sess, time.Hour)
		}()

		// Get
		go func() {
			defer wg.Done()
			_, _ = ms.GetSession(ctx, id)
		}()

		// Delete
		go func() {
			defer wg.Done()
			_ = ms.DeleteSession(ctx, id)
		}()
	}

	wg.Wait()
}

// --- AuthCode テスト ---

func testAuthCodeData() *idproxy.AuthCodeData {
	now := time.Now()
	return &idproxy.AuthCodeData{
		Code:                "code-abc123",
		ClientID:            "client-001",
		RedirectURI:         "https://app.example.com/callback",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		Scopes:              []string{"openid", "profile"},
		User:                &idproxy.User{Email: "test@example.com", Subject: "sub-001"},
		CreatedAt:           now,
		ExpiresAt:           now.Add(10 * time.Minute),
	}
}

func TestMemoryStore_SetGetAuthCode(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	data := testAuthCodeData()

	if err := ms.SetAuthCode(ctx, data.Code, data, time.Hour); err != nil {
		t.Fatalf("SetAuthCode() error = %v", err)
	}

	got, err := ms.GetAuthCode(ctx, data.Code)
	if err != nil {
		t.Fatalf("GetAuthCode() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetAuthCode() returned nil")
	}
	if got.Code != data.Code {
		t.Errorf("Code = %q, want %q", got.Code, data.Code)
	}
	if got.ClientID != data.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, data.ClientID)
	}
	if got.RedirectURI != data.RedirectURI {
		t.Errorf("RedirectURI = %q, want %q", got.RedirectURI, data.RedirectURI)
	}
	if len(got.Scopes) != len(data.Scopes) {
		t.Errorf("Scopes = %v, want %v", got.Scopes, data.Scopes)
	}
	if got.User == nil || got.User.Email != data.User.Email {
		t.Errorf("User.Email = %v, want %v", got.User, data.User)
	}
}

func TestMemoryStore_GetAuthCode_NotFound(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()

	got, err := ms.GetAuthCode(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetAuthCode() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetAuthCode() = %v, want nil", got)
	}
}

func TestMemoryStore_GetAuthCode_Expired(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	data := testAuthCodeData()

	// TTL を 1ns に設定して即時期限切れ
	if err := ms.SetAuthCode(ctx, data.Code, data, time.Nanosecond); err != nil {
		t.Fatalf("SetAuthCode() error = %v", err)
	}
	// 少し待って確実に期限切れにする
	time.Sleep(time.Millisecond)

	got, err := ms.GetAuthCode(ctx, data.Code)
	if err != nil {
		t.Fatalf("GetAuthCode() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetAuthCode() = %v, want nil (expired)", got)
	}
}

func TestMemoryStore_SetAuthCode_Overwrite(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()

	data1 := testAuthCodeData()
	data2 := testAuthCodeData()
	data2.ClientID = "client-updated"

	if err := ms.SetAuthCode(ctx, data1.Code, data1, time.Hour); err != nil {
		t.Fatalf("SetAuthCode(1) error = %v", err)
	}
	if err := ms.SetAuthCode(ctx, data1.Code, data2, time.Hour); err != nil {
		t.Fatalf("SetAuthCode(2) error = %v", err)
	}

	got, err := ms.GetAuthCode(ctx, data1.Code)
	if err != nil {
		t.Fatalf("GetAuthCode() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetAuthCode() returned nil")
	}
	if got.ClientID != "client-updated" {
		t.Errorf("ClientID = %q, want %q", got.ClientID, "client-updated")
	}
}

func TestMemoryStore_DeleteAuthCode(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	data := testAuthCodeData()

	if err := ms.SetAuthCode(ctx, data.Code, data, time.Hour); err != nil {
		t.Fatalf("SetAuthCode() error = %v", err)
	}
	if err := ms.DeleteAuthCode(ctx, data.Code); err != nil {
		t.Fatalf("DeleteAuthCode() error = %v", err)
	}

	got, err := ms.GetAuthCode(ctx, data.Code)
	if err != nil {
		t.Fatalf("GetAuthCode() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetAuthCode() = %v, want nil (deleted)", got)
	}
}

func TestMemoryStore_DeleteAuthCode_NotFound(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()

	if err := ms.DeleteAuthCode(ctx, "nonexistent"); err != nil {
		t.Errorf("DeleteAuthCode() error = %v, want nil", err)
	}
}

func TestMemoryStore_SetAuthCode_ContextCanceled(t *testing.T) {
	ms := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	data := testAuthCodeData()

	err := ms.SetAuthCode(ctx, data.Code, data, time.Hour)
	if err != context.Canceled {
		t.Errorf("SetAuthCode() error = %v, want %v", err, context.Canceled)
	}
}

func TestMemoryStore_GetAuthCode_ContextCanceled(t *testing.T) {
	ms := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := ms.GetAuthCode(ctx, "any")
	if err != context.Canceled {
		t.Errorf("GetAuthCode() error = %v, want %v", err, context.Canceled)
	}
	if got != nil {
		t.Errorf("GetAuthCode() = %v, want nil", got)
	}
}

func TestMemoryStore_DeleteAuthCode_ContextCanceled(t *testing.T) {
	ms := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := ms.DeleteAuthCode(ctx, "any")
	if err != context.Canceled {
		t.Errorf("DeleteAuthCode() error = %v, want %v", err, context.Canceled)
	}
}

// --- AccessToken テスト ---

func testAccessTokenData() *idproxy.AccessTokenData {
	now := time.Now()
	return &idproxy.AccessTokenData{
		JTI:       "jti-xyz789",
		Subject:   "sub-001",
		Email:     "test@example.com",
		ClientID:  "client-001",
		Scopes:    []string{"openid", "profile"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		Revoked:   false,
	}
}

func TestMemoryStore_SetGetAccessToken(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	data := testAccessTokenData()

	if err := ms.SetAccessToken(ctx, data.JTI, data, time.Hour); err != nil {
		t.Fatalf("SetAccessToken() error = %v", err)
	}

	got, err := ms.GetAccessToken(ctx, data.JTI)
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetAccessToken() returned nil")
	}
	if got.JTI != data.JTI {
		t.Errorf("JTI = %q, want %q", got.JTI, data.JTI)
	}
	if got.Subject != data.Subject {
		t.Errorf("Subject = %q, want %q", got.Subject, data.Subject)
	}
	if got.Email != data.Email {
		t.Errorf("Email = %q, want %q", got.Email, data.Email)
	}
	if got.ClientID != data.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, data.ClientID)
	}
	if len(got.Scopes) != len(data.Scopes) {
		t.Errorf("Scopes = %v, want %v", got.Scopes, data.Scopes)
	}
	if got.Revoked != data.Revoked {
		t.Errorf("Revoked = %v, want %v", got.Revoked, data.Revoked)
	}
}

func TestMemoryStore_GetAccessToken_NotFound(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()

	got, err := ms.GetAccessToken(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetAccessToken() = %v, want nil", got)
	}
}

func TestMemoryStore_GetAccessToken_Expired(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	data := testAccessTokenData()

	// TTL を 1ns に設定して即時期限切れ
	if err := ms.SetAccessToken(ctx, data.JTI, data, time.Nanosecond); err != nil {
		t.Fatalf("SetAccessToken() error = %v", err)
	}
	// 少し待って確実に期限切れにする
	time.Sleep(time.Millisecond)

	got, err := ms.GetAccessToken(ctx, data.JTI)
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetAccessToken() = %v, want nil (expired)", got)
	}
}

func TestMemoryStore_SetAccessToken_Overwrite(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()

	data1 := testAccessTokenData()
	data2 := testAccessTokenData()
	data2.Revoked = true

	if err := ms.SetAccessToken(ctx, data1.JTI, data1, time.Hour); err != nil {
		t.Fatalf("SetAccessToken(1) error = %v", err)
	}
	if err := ms.SetAccessToken(ctx, data1.JTI, data2, time.Hour); err != nil {
		t.Fatalf("SetAccessToken(2) error = %v", err)
	}

	got, err := ms.GetAccessToken(ctx, data1.JTI)
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetAccessToken() returned nil")
	}
	if !got.Revoked {
		t.Errorf("Revoked = %v, want true", got.Revoked)
	}
}

func TestMemoryStore_DeleteAccessToken(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	data := testAccessTokenData()

	if err := ms.SetAccessToken(ctx, data.JTI, data, time.Hour); err != nil {
		t.Fatalf("SetAccessToken() error = %v", err)
	}
	if err := ms.DeleteAccessToken(ctx, data.JTI); err != nil {
		t.Fatalf("DeleteAccessToken() error = %v", err)
	}

	got, err := ms.GetAccessToken(ctx, data.JTI)
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetAccessToken() = %v, want nil (deleted)", got)
	}
}

func TestMemoryStore_DeleteAccessToken_NotFound(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()

	if err := ms.DeleteAccessToken(ctx, "nonexistent"); err != nil {
		t.Errorf("DeleteAccessToken() error = %v, want nil", err)
	}
}

func TestMemoryStore_SetAccessToken_ContextCanceled(t *testing.T) {
	ms := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	data := testAccessTokenData()

	err := ms.SetAccessToken(ctx, data.JTI, data, time.Hour)
	if err != context.Canceled {
		t.Errorf("SetAccessToken() error = %v, want %v", err, context.Canceled)
	}
}

func TestMemoryStore_GetAccessToken_ContextCanceled(t *testing.T) {
	ms := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := ms.GetAccessToken(ctx, "any")
	if err != context.Canceled {
		t.Errorf("GetAccessToken() error = %v, want %v", err, context.Canceled)
	}
	if got != nil {
		t.Errorf("GetAccessToken() = %v, want nil", got)
	}
}

func TestMemoryStore_DeleteAccessToken_ContextCanceled(t *testing.T) {
	ms := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := ms.DeleteAccessToken(ctx, "any")
	if err != context.Canceled {
		t.Errorf("DeleteAccessToken() error = %v, want %v", err, context.Canceled)
	}
}

// --- 複合並行テスト ---

func TestMemoryStore_Concurrent_AllTypes(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines * 9) // Session + AuthCode + AccessToken × 3操作

	for i := range goroutines {
		idx := i % 26
		sessID := "sess-" + string(rune('A'+idx))
		codeID := "code-" + string(rune('A'+idx))
		jtiID := "jti-" + string(rune('A'+idx))

		sess := &idproxy.Session{ID: sessID, User: &idproxy.User{Email: sessID + "@example.com"}}
		authCode := &idproxy.AuthCodeData{Code: codeID, ClientID: "client-" + string(rune('A'+idx))}
		token := &idproxy.AccessTokenData{JTI: jtiID, Subject: "sub-" + string(rune('A'+idx))}

		// Session
		go func() { defer wg.Done(); _ = ms.SetSession(ctx, sessID, sess, time.Hour) }()
		go func() { defer wg.Done(); _, _ = ms.GetSession(ctx, sessID) }()
		go func() { defer wg.Done(); _ = ms.DeleteSession(ctx, sessID) }()

		// AuthCode
		go func() { defer wg.Done(); _ = ms.SetAuthCode(ctx, codeID, authCode, time.Hour) }()
		go func() { defer wg.Done(); _, _ = ms.GetAuthCode(ctx, codeID) }()
		go func() { defer wg.Done(); _ = ms.DeleteAuthCode(ctx, codeID) }()

		// AccessToken
		go func() { defer wg.Done(); _ = ms.SetAccessToken(ctx, jtiID, token, time.Hour) }()
		go func() { defer wg.Done(); _, _ = ms.GetAccessToken(ctx, jtiID) }()
		go func() { defer wg.Done(); _ = ms.DeleteAccessToken(ctx, jtiID) }()
	}

	wg.Wait()
}

// --- Cleanup / Close テスト ---

// newTestMemoryStore はテスト専用コンストラクタ。
// バックグラウンド goroutine を起動せず、goroutine リークを防止する。
func newTestMemoryStore() *MemoryStore {
	return newMemoryStoreWithInterval(0)
}

func TestMemoryStore_Cleanup_RemovesExpiredSessions(t *testing.T) {
	ms := newTestMemoryStore()
	defer ms.Close() //nolint:errcheck
	ctx := context.Background()

	_ = ms.SetSession(ctx, "expired", testSession(), -time.Second)
	_ = ms.SetSession(ctx, "valid", testSession(), time.Hour)

	err := ms.Cleanup(ctx)
	if err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	got, _ := ms.GetSession(ctx, "expired")
	if got != nil {
		t.Error("expired session should be nil after Cleanup")
	}
	got, _ = ms.GetSession(ctx, "valid")
	if got == nil {
		t.Error("valid session should remain after Cleanup")
	}
}

func TestMemoryStore_Cleanup_RemovesExpiredAuthCodes(t *testing.T) {
	ms := newTestMemoryStore()
	defer ms.Close() //nolint:errcheck
	ctx := context.Background()

	_ = ms.SetAuthCode(ctx, "expired-code", testAuthCodeData(), -time.Second)
	_ = ms.SetAuthCode(ctx, "valid-code", testAuthCodeData(), time.Hour)

	err := ms.Cleanup(ctx)
	if err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	got, _ := ms.GetAuthCode(ctx, "expired-code")
	if got != nil {
		t.Error("expired auth code should be nil after Cleanup")
	}
	got, _ = ms.GetAuthCode(ctx, "valid-code")
	if got == nil {
		t.Error("valid auth code should remain after Cleanup")
	}
}

func TestMemoryStore_Cleanup_RemovesExpiredAccessTokens(t *testing.T) {
	ms := newTestMemoryStore()
	defer ms.Close() //nolint:errcheck
	ctx := context.Background()

	_ = ms.SetAccessToken(ctx, "expired-jti", testAccessTokenData(), -time.Second)
	_ = ms.SetAccessToken(ctx, "valid-jti", testAccessTokenData(), time.Hour)

	err := ms.Cleanup(ctx)
	if err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	got, _ := ms.GetAccessToken(ctx, "expired-jti")
	if got != nil {
		t.Error("expired access token should be nil after Cleanup")
	}
	got, _ = ms.GetAccessToken(ctx, "valid-jti")
	if got == nil {
		t.Error("valid access token should remain after Cleanup")
	}
}

func TestMemoryStore_Cleanup_AllTypes(t *testing.T) {
	ms := newTestMemoryStore()
	defer ms.Close() //nolint:errcheck
	ctx := context.Background()

	// 3マップそれぞれに期限切れ・有効エントリを設定
	_ = ms.SetSession(ctx, "sess-exp", testSession(), -time.Second)
	_ = ms.SetSession(ctx, "sess-ok", testSession(), time.Hour)
	_ = ms.SetAuthCode(ctx, "code-exp", testAuthCodeData(), -time.Second)
	_ = ms.SetAuthCode(ctx, "code-ok", testAuthCodeData(), time.Hour)
	_ = ms.SetAccessToken(ctx, "jti-exp", testAccessTokenData(), -time.Second)
	_ = ms.SetAccessToken(ctx, "jti-ok", testAccessTokenData(), time.Hour)

	err := ms.Cleanup(ctx)
	if err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	// 期限切れは削除済み
	s, _ := ms.GetSession(ctx, "sess-exp")
	if s != nil {
		t.Error("sess-exp should be deleted")
	}
	c, _ := ms.GetAuthCode(ctx, "code-exp")
	if c != nil {
		t.Error("code-exp should be deleted")
	}
	a, _ := ms.GetAccessToken(ctx, "jti-exp")
	if a != nil {
		t.Error("jti-exp should be deleted")
	}

	// 有効エントリは残存
	s, _ = ms.GetSession(ctx, "sess-ok")
	if s == nil {
		t.Error("sess-ok should remain")
	}
	c, _ = ms.GetAuthCode(ctx, "code-ok")
	if c == nil {
		t.Error("code-ok should remain")
	}
	a, _ = ms.GetAccessToken(ctx, "jti-ok")
	if a == nil {
		t.Error("jti-ok should remain")
	}
}

// --- RefreshToken テスト ---

func testRefreshTokenData() *idproxy.RefreshTokenData {
	now := time.Now()
	return &idproxy.RefreshTokenData{
		ID:        "rt-opaque-001",
		FamilyID:  "family-uuid-001",
		ClientID:  "client-001",
		Subject:   "sub-001",
		Email:     "test@example.com",
		Name:      "Test User",
		Scopes:    []string{"openid", "profile"},
		IssuedAt:  now,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
		Used:      false,
	}
}

// RT01: SetRefreshToken → GetRefreshToken で同一値が取得できること
func TestMemoryStore_RT01_SetGetRefreshToken(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	data := testRefreshTokenData()

	if err := ms.SetRefreshToken(ctx, data.ID, data, time.Hour); err != nil {
		t.Fatalf("SetRefreshToken() error = %v", err)
	}

	got, err := ms.GetRefreshToken(ctx, data.ID)
	if err != nil {
		t.Fatalf("GetRefreshToken() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetRefreshToken() returned nil")
	}
	if got.ID != data.ID {
		t.Errorf("ID = %q, want %q", got.ID, data.ID)
	}
	if got.FamilyID != data.FamilyID {
		t.Errorf("FamilyID = %q, want %q", got.FamilyID, data.FamilyID)
	}
	if got.ClientID != data.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, data.ClientID)
	}
	if got.Subject != data.Subject {
		t.Errorf("Subject = %q, want %q", got.Subject, data.Subject)
	}
	if got.Used {
		t.Error("Used = true, want false")
	}
}

// RT02: GetRefreshToken 未登録は (nil, nil)
func TestMemoryStore_RT02_GetRefreshToken_NotFound(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()

	got, err := ms.GetRefreshToken(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetRefreshToken() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetRefreshToken() = %v, want nil", got)
	}
}

// RT03: GetRefreshToken TTL 切れは (nil, nil)
func TestMemoryStore_RT03_GetRefreshToken_Expired(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	data := testRefreshTokenData()

	if err := ms.SetRefreshToken(ctx, data.ID, data, time.Nanosecond); err != nil {
		t.Fatalf("SetRefreshToken() error = %v", err)
	}
	time.Sleep(time.Millisecond)

	got, err := ms.GetRefreshToken(ctx, data.ID)
	if err != nil {
		t.Fatalf("GetRefreshToken() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetRefreshToken() = %v, want nil (expired)", got)
	}
}

// RT04: ConsumeRefreshToken 初回消費 — Used=true に更新され、data が返る
func TestMemoryStore_RT04_ConsumeRefreshToken_FirstConsume(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	data := testRefreshTokenData()

	if err := ms.SetRefreshToken(ctx, data.ID, data, time.Hour); err != nil {
		t.Fatalf("SetRefreshToken() error = %v", err)
	}

	got, err := ms.ConsumeRefreshToken(ctx, data.ID)
	if err != nil {
		t.Fatalf("ConsumeRefreshToken() error = %v, want nil", err)
	}
	if got == nil {
		t.Fatal("ConsumeRefreshToken() returned nil")
	}
	if !got.Used {
		t.Error("Used = false, want true (should be marked as used)")
	}
	if got.FamilyID != data.FamilyID {
		t.Errorf("FamilyID = %q, want %q", got.FamilyID, data.FamilyID)
	}

	// Store 上のエントリも Used=true になっていること
	stored, _ := ms.GetRefreshToken(ctx, data.ID)
	if stored == nil {
		t.Fatal("GetRefreshToken() after consume returned nil")
	}
	if !stored.Used {
		t.Error("stored Used = false, want true after consume")
	}
}

// RT05: ConsumeRefreshToken 2回目 — (data, ErrRefreshTokenAlreadyConsumed) が返る
func TestMemoryStore_RT05_ConsumeRefreshToken_SecondConsume(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	data := testRefreshTokenData()

	if err := ms.SetRefreshToken(ctx, data.ID, data, time.Hour); err != nil {
		t.Fatalf("SetRefreshToken() error = %v", err)
	}

	// 1回目の消費
	got1, err := ms.ConsumeRefreshToken(ctx, data.ID)
	if err != nil {
		t.Fatalf("first ConsumeRefreshToken() error = %v, want nil", err)
	}
	if got1 == nil {
		t.Fatal("first ConsumeRefreshToken() returned nil")
	}

	// 2回目の消費
	got2, err := ms.ConsumeRefreshToken(ctx, data.ID)
	if err == nil {
		t.Fatal("second ConsumeRefreshToken() error = nil, want ErrRefreshTokenAlreadyConsumed")
	}
	if err != idproxy.ErrRefreshTokenAlreadyConsumed {
		t.Errorf("second ConsumeRefreshToken() error = %v, want %v", err, idproxy.ErrRefreshTokenAlreadyConsumed)
	}
	if got2 == nil {
		t.Fatal("second ConsumeRefreshToken() returned nil data, want data with FamilyID")
	}
	if got2.FamilyID != data.FamilyID {
		t.Errorf("FamilyID = %q, want %q (for replay detection)", got2.FamilyID, data.FamilyID)
	}
}

// RT06: ConsumeRefreshToken 未登録 — (nil, nil)
func TestMemoryStore_RT06_ConsumeRefreshToken_NotFound(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()

	got, err := ms.ConsumeRefreshToken(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("ConsumeRefreshToken() error = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("ConsumeRefreshToken() = %v, want nil", got)
	}
}

// RT07: ConsumeRefreshToken TTL 切れ — (nil, nil)
func TestMemoryStore_RT07_ConsumeRefreshToken_Expired(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	data := testRefreshTokenData()

	if err := ms.SetRefreshToken(ctx, data.ID, data, time.Nanosecond); err != nil {
		t.Fatalf("SetRefreshToken() error = %v", err)
	}
	time.Sleep(time.Millisecond)

	got, err := ms.ConsumeRefreshToken(ctx, data.ID)
	if err != nil {
		t.Fatalf("ConsumeRefreshToken() error = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("ConsumeRefreshToken() = %v, want nil (expired)", got)
	}
}

// RT08: SetFamilyRevocation → IsFamilyRevoked=true
func TestMemoryStore_RT08_SetFamilyRevocation(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	familyID := "family-uuid-001"

	if err := ms.SetFamilyRevocation(ctx, familyID, time.Hour); err != nil {
		t.Fatalf("SetFamilyRevocation() error = %v", err)
	}

	revoked, err := ms.IsFamilyRevoked(ctx, familyID)
	if err != nil {
		t.Fatalf("IsFamilyRevoked() error = %v", err)
	}
	if !revoked {
		t.Error("IsFamilyRevoked() = false, want true")
	}
}

// RT09: 未設定 family → IsFamilyRevoked=false
func TestMemoryStore_RT09_IsFamilyRevoked_NotSet(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()

	revoked, err := ms.IsFamilyRevoked(ctx, "unknown-family")
	if err != nil {
		t.Fatalf("IsFamilyRevoked() error = %v", err)
	}
	if revoked {
		t.Error("IsFamilyRevoked() = true, want false")
	}
}

// RT10: SetFamilyRevocation TTL 切れ → IsFamilyRevoked=false
func TestMemoryStore_RT10_IsFamilyRevoked_Expired(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	familyID := "family-uuid-expired"

	if err := ms.SetFamilyRevocation(ctx, familyID, time.Nanosecond); err != nil {
		t.Fatalf("SetFamilyRevocation() error = %v", err)
	}
	time.Sleep(time.Millisecond)

	revoked, err := ms.IsFamilyRevoked(ctx, familyID)
	if err != nil {
		t.Fatalf("IsFamilyRevoked() error = %v", err)
	}
	if revoked {
		t.Error("IsFamilyRevoked() = true, want false (expired)")
	}
}

// RT11: ConsumeRefreshToken race condition — 複数 goroutine で同時消費、片方のみ成功
func TestMemoryStore_RT11_ConsumeRefreshToken_Race(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	data := testRefreshTokenData()

	if err := ms.SetRefreshToken(ctx, data.ID, data, time.Hour); err != nil {
		t.Fatalf("SetRefreshToken() error = %v", err)
	}

	const goroutines = 20
	results := make([]error, goroutines)
	datas := make([]*idproxy.RefreshTokenData, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		idx := i
		go func() {
			defer wg.Done()
			d, err := ms.ConsumeRefreshToken(ctx, data.ID)
			results[idx] = err
			datas[idx] = d
		}()
	}
	wg.Wait()

	// 成功 (nil error) は1回のみ、残りは ErrRefreshTokenAlreadyConsumed または nil data (not found)
	successCount := 0
	alreadyConsumedCount := 0
	for i, err := range results {
		if err == nil && datas[i] != nil {
			successCount++
		} else if err == idproxy.ErrRefreshTokenAlreadyConsumed {
			alreadyConsumedCount++
			if datas[i] == nil {
				t.Errorf("goroutine %d: ErrRefreshTokenAlreadyConsumed but data is nil, want data with FamilyID", i)
			}
		}
	}

	if successCount != 1 {
		t.Errorf("successCount = %d, want 1 (only one goroutine should succeed)", successCount)
	}
}

// --- Cleanup でリフレッシュトークン関連エントリが削除されること ---

func TestMemoryStore_Cleanup_RemovesExpiredRefreshTokens(t *testing.T) {
	ms := newTestMemoryStore()
	defer ms.Close() //nolint:errcheck
	ctx := context.Background()

	_ = ms.SetRefreshToken(ctx, "rt-expired", testRefreshTokenData(), -time.Second)
	_ = ms.SetRefreshToken(ctx, "rt-valid", testRefreshTokenData(), time.Hour)

	if err := ms.Cleanup(ctx); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	got, _ := ms.GetRefreshToken(ctx, "rt-expired")
	if got != nil {
		t.Error("expired refresh token should be nil after Cleanup")
	}
	got, _ = ms.GetRefreshToken(ctx, "rt-valid")
	if got == nil {
		t.Error("valid refresh token should remain after Cleanup")
	}
}

func TestMemoryStore_Cleanup_RemovesExpiredFamilyRevocations(t *testing.T) {
	ms := newTestMemoryStore()
	defer ms.Close() //nolint:errcheck
	ctx := context.Background()

	_ = ms.SetFamilyRevocation(ctx, "family-expired", -time.Second)
	_ = ms.SetFamilyRevocation(ctx, "family-valid", time.Hour)

	if err := ms.Cleanup(ctx); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	revoked, _ := ms.IsFamilyRevoked(ctx, "family-expired")
	if revoked {
		t.Error("expired family revocation should be removed after Cleanup")
	}
	revoked, _ = ms.IsFamilyRevoked(ctx, "family-valid")
	if !revoked {
		t.Error("valid family revocation should remain after Cleanup")
	}
}

func TestMemoryStore_Close_Idempotent(t *testing.T) {
	ms := NewMemoryStore()

	// 二重 Close がパニックしないこと
	if err := ms.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := ms.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestMemoryStore_Cleanup_OnlyValid(t *testing.T) {
	ms := newTestMemoryStore()
	defer ms.Close() //nolint:errcheck
	ctx := context.Background()

	// 有効エントリのみ — Cleanup 後も全て残ること
	_ = ms.SetSession(ctx, "s1", testSession(), time.Hour)
	_ = ms.SetSession(ctx, "s2", testSession(), time.Hour)

	if err := ms.Cleanup(ctx); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	for _, id := range []string{"s1", "s2"} {
		got, _ := ms.GetSession(ctx, id)
		if got == nil {
			t.Errorf("session %s should remain after Cleanup with no expired entries", id)
		}
	}
}
