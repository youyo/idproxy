package idproxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// --- OAuthServer テスト用ヘルパー ---

// setupOAuthServer はテスト用の OAuthServer を構築する。
func setupOAuthServer(t *testing.T, externalURL, pathPrefix string) *OAuthServer {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	st := newTestMemoryStore()

	cfg := Config{
		Providers: []OIDCProvider{
			{
				Issuer:       "https://accounts.google.com",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		},
		ExternalURL:  externalURL,
		CookieSecret: []byte("test-cookie-secret-32-bytes-long!"),
		PathPrefix:   pathPrefix,
		Store:        st,
		OAuth: &OAuthConfig{
			SigningKey: privateKey,
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate() failed: %v", err)
	}

	srv, err := NewOAuthServer(cfg, st, nil)
	if err != nil {
		t.Fatalf("NewOAuthServer() failed: %v", err)
	}

	return srv
}

// --- NewOAuthServer テスト ---

func TestNewOAuthServer_Success(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "")
	if srv == nil {
		t.Fatal("NewOAuthServer() returned nil")
	}
}

func TestNewOAuthServer_WithOAuthConfigSigningKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	st := newTestMemoryStore()
	cfg := Config{
		Providers: []OIDCProvider{
			{
				Issuer:       "https://accounts.google.com",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		},
		ExternalURL:  "http://localhost:8080",
		CookieSecret: []byte("test-cookie-secret-32-bytes-long!"),
		Store:        st,
		OAuth: &OAuthConfig{
			SigningKey: privateKey,
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate() failed: %v", err)
	}

	srv, err := NewOAuthServer(cfg, st, nil)
	if err != nil {
		t.Fatalf("NewOAuthServer() failed: %v", err)
	}

	if srv == nil {
		t.Fatal("NewOAuthServer() returned nil")
	}
}

func TestNewOAuthServer_NilOAuthConfig(t *testing.T) {
	st := newTestMemoryStore()
	cfg := Config{
		Providers: []OIDCProvider{
			{
				Issuer:       "https://accounts.google.com",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		},
		ExternalURL:  "http://localhost:8080",
		CookieSecret: []byte("test-cookie-secret-32-bytes-long!"),
		Store:        st,
		// OAuth is nil - should generate key pair
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate() failed: %v", err)
	}

	srv, err := NewOAuthServer(cfg, st, nil)
	if err != nil {
		t.Fatalf("NewOAuthServer() should succeed even without OAuth config (auto-generate key): %v", err)
	}
	if srv == nil {
		t.Fatal("NewOAuthServer() returned nil")
	}
}

func TestNewOAuthServer_NonECDSAKey(t *testing.T) {
	// RSA key は ES256 と互換性がないのでエラーになるべき
	// ただし OAuthConfig が nil の場合は自動生成するため、
	// 明示的に非 ECDSA 鍵を渡すケースをテストする
	// → この場合 Config.Validate() がエラーを返すので、
	// NewOAuthServer 側でもエラー処理をすべき

	// ここでは ECDSA P-256 以外のケースとして P-384 を使う
	key384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate P-384 key: %v", err)
	}

	st := newTestMemoryStore()
	cfg := Config{
		Providers: []OIDCProvider{
			{
				Issuer:       "https://accounts.google.com",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		},
		ExternalURL:  "http://localhost:8080",
		CookieSecret: []byte("test-cookie-secret-32-bytes-long!"),
		Store:        st,
		OAuth: &OAuthConfig{
			SigningKey: key384,
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate() failed: %v", err)
	}

	_, err = NewOAuthServer(cfg, st, nil)
	if err == nil {
		t.Fatal("NewOAuthServer() should return error for non P-256 ECDSA key")
	}
}

// --- メタデータエンドポイントテスト ---

func TestOAuthServer_Metadata_NoPrefix(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Content-Type チェック
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	// JSON パース
	var meta map[string]any
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("failed to decode metadata JSON: %v", err)
	}

	// RFC 8414 必須フィールド検証
	assertStringField(t, meta, "issuer", "http://localhost:8080")
	assertStringField(t, meta, "authorization_endpoint", "http://localhost:8080/authorize")
	assertStringField(t, meta, "token_endpoint", "http://localhost:8080/token")
	assertStringField(t, meta, "registration_endpoint", "http://localhost:8080/register")
	assertStringField(t, meta, "jwks_uri", "http://localhost:8080/.well-known/jwks.json")

	// サポートされる値の検証
	assertStringSliceField(t, meta, "response_types_supported", []string{"code"})
	assertStringSliceField(t, meta, "grant_types_supported", []string{"authorization_code", "refresh_token"})
	assertStringSliceField(t, meta, "code_challenge_methods_supported", []string{"S256"})
	assertStringSliceField(t, meta, "token_endpoint_auth_methods_supported", []string{"none"})
	assertStringSliceField(t, meta, "scopes_supported", []string{"openid", "email", "profile"})
}

func TestOAuthServer_Metadata_WithPathPrefix(t *testing.T) {
	srv := setupOAuthServer(t, "https://example.com", "/auth")

	req := httptest.NewRequest(http.MethodGet, "/auth/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var meta map[string]any
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("failed to decode metadata JSON: %v", err)
	}

	// PathPrefix 付きエンドポイント URL の検証
	assertStringField(t, meta, "issuer", "https://example.com")
	assertStringField(t, meta, "authorization_endpoint", "https://example.com/auth/authorize")
	assertStringField(t, meta, "token_endpoint", "https://example.com/auth/token")
	assertStringField(t, meta, "registration_endpoint", "https://example.com/auth/register")
	assertStringField(t, meta, "jwks_uri", "https://example.com/auth/.well-known/jwks.json")
}

func TestOAuthServer_Metadata_MethodNotAllowed(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "")

	// POST メソッドは許可されない
	req := httptest.NewRequest(http.MethodPost, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

// --- JWKS エンドポイントテスト ---

func TestOAuthServer_JWKS(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	// JWKS JSON パース
	var jwks map[string]any
	if err := json.NewDecoder(w.Body).Decode(&jwks); err != nil {
		t.Fatalf("failed to decode JWKS JSON: %v", err)
	}

	keys, ok := jwks["keys"].([]any)
	if !ok {
		t.Fatal("JWKS response should have 'keys' array")
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key in JWKS, got %d", len(keys))
	}

	key := keys[0].(map[string]any)
	assertStringField(t, key, "kty", "EC")
	assertStringField(t, key, "crv", "P-256")
	assertStringField(t, key, "use", "sig")
	assertStringField(t, key, "alg", "ES256")

	// x, y, kid が存在することを確認
	if _, ok := key["x"]; !ok {
		t.Error("JWKS key should have 'x' field")
	}
	if _, ok := key["y"]; !ok {
		t.Error("JWKS key should have 'y' field")
	}
	if _, ok := key["kid"]; !ok {
		t.Error("JWKS key should have 'kid' field")
	}
}

func TestOAuthServer_JWKS_WithPathPrefix(t *testing.T) {
	srv := setupOAuthServer(t, "https://example.com", "/auth")

	req := httptest.NewRequest(http.MethodGet, "/auth/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var jwks map[string]any
	if err := json.NewDecoder(w.Body).Decode(&jwks); err != nil {
		t.Fatalf("failed to decode JWKS JSON: %v", err)
	}

	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) != 1 {
		t.Fatal("JWKS should have exactly 1 key")
	}
}

func TestOAuthServer_JWKS_MethodNotAllowed(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "")

	req := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

// --- ServeHTTP ルーティングテスト ---

func TestOAuthServer_ServeHTTP_UnknownPath(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "")

	req := httptest.NewRequest(http.MethodGet, "/unknown-path", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

// --- Auth 統合テスト ---

func TestAuth_SetOAuthServer_MetadataRouting(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "")

	st := newTestMemoryStore()
	cfg := Config{
		Providers: []OIDCProvider{
			{
				Issuer:       "https://accounts.google.com",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		},
		ExternalURL:  "http://localhost:8080",
		CookieSecret: []byte("test-cookie-secret-32-bytes-long!"),
		Store:        st,
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate() failed: %v", err)
	}

	// Auth.New は ProviderManager を作るために実際の OIDC Discovery が必要なので、
	// ここでは Auth を直接構築しない。
	// 代わりに、OAuthServer が http.Handler として正しく動作することを確認する。

	// OAuthServer が http.Handler インターフェースを実装していることを確認
	var _ http.Handler = srv
}

// --- テスト用ヘルパー ---

func assertStringField(t *testing.T, m map[string]any, key, expected string) {
	t.Helper()
	val, ok := m[key]
	if !ok {
		t.Errorf("missing field %q", key)
		return
	}
	str, ok := val.(string)
	if !ok {
		t.Errorf("field %q is not a string: %v", key, val)
		return
	}
	if str != expected {
		t.Errorf("field %q: expected %q, got %q", key, expected, str)
	}
}

// --- /authorize エンドポイント用ヘルパー ---

// setupAuthorizeServer はテスト用の OAuthServer を SessionManager 付きで構築する。
func setupAuthorizeServer(t *testing.T) (*OAuthServer, *SessionManager, *testMemoryStore) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	st := newTestMemoryStore()

	cfg := Config{
		Providers: []OIDCProvider{
			{
				Issuer:       "https://accounts.google.com",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		},
		ExternalURL:  "http://localhost:8080",
		CookieSecret: bytes.Repeat([]byte("a"), 32),
		PathPrefix:   "",
		Store:        st,
		OAuth: &OAuthConfig{
			SigningKey:          privateKey,
			ClientID:            "test-oauth-client",
			AllowedRedirectURIs: []string{"http://localhost:3000/callback", "https://app.example.com/callback"},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate() failed: %v", err)
	}

	sm, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("NewSessionManager() failed: %v", err)
	}

	srv, err := NewOAuthServer(cfg, st, sm)
	if err != nil {
		t.Fatalf("NewOAuthServer() failed: %v", err)
	}

	return srv, sm, st
}

// issueTestSession はテスト用セッションを発行し、Cookie を持つ *http.Request を返すヘルパー。
func issueTestSession(t *testing.T, sm *SessionManager) []*http.Cookie {
	t.Helper()
	ctx := context.Background()
	user := &User{
		Email:   "test@example.com",
		Name:    "Test User",
		Subject: "sub-123",
		Issuer:  "https://accounts.google.com",
	}
	sess, err := sm.IssueSession(ctx, user, "https://accounts.google.com", "raw-id-token")
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	w := httptest.NewRecorder()
	if err := sm.SetCookie(w, sess.ID); err != nil {
		t.Fatalf("SetCookie: %v", err)
	}
	return w.Result().Cookies()
}

// validAuthorizeQuery は正常な /authorize クエリパラメータを返す。
func validAuthorizeQuery() url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {"test-oauth-client"},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"state":                 {"random-state-value"},
		"scope":                 {"openid"},
	}
}

// --- /authorize テスト: パラメータ検証（異常系） ---

func TestAuthorize_MethodNotAllowed(t *testing.T) {
	srv, _, _ := setupAuthorizeServer(t)

	req := httptest.NewRequest(http.MethodPost, "/authorize?"+validAuthorizeQuery().Encode(), nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestAuthorize_MissingResponseType(t *testing.T) {
	srv, _, _ := setupAuthorizeServer(t)
	q := validAuthorizeQuery()
	q.Del("response_type")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_request")
}

func TestAuthorize_InvalidResponseType(t *testing.T) {
	srv, _, _ := setupAuthorizeServer(t)
	q := validAuthorizeQuery()
	q.Set("response_type", "token")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_request")
}

func TestAuthorize_MissingClientID(t *testing.T) {
	srv, _, _ := setupAuthorizeServer(t)
	q := validAuthorizeQuery()
	q.Del("client_id")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_request")
}

func TestAuthorize_InvalidClientID(t *testing.T) {
	srv, _, _ := setupAuthorizeServer(t)
	q := validAuthorizeQuery()
	q.Set("client_id", "wrong-client-id")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_client")
}

func TestAuthorize_MissingRedirectURI(t *testing.T) {
	srv, _, _ := setupAuthorizeServer(t)
	q := validAuthorizeQuery()
	q.Del("redirect_uri")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_request")
}

func TestAuthorize_DisallowedRedirectURI(t *testing.T) {
	srv, _, _ := setupAuthorizeServer(t)
	q := validAuthorizeQuery()
	q.Set("redirect_uri", "https://evil.example.com/callback")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_request")
}

func TestAuthorize_MissingCodeChallenge(t *testing.T) {
	srv, _, _ := setupAuthorizeServer(t)
	q := validAuthorizeQuery()
	q.Del("code_challenge")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_request")
}

func TestAuthorize_InvalidCodeChallengeMethod(t *testing.T) {
	srv, _, _ := setupAuthorizeServer(t)
	q := validAuthorizeQuery()
	q.Set("code_challenge_method", "plain")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_request")
}

func TestAuthorize_MissingCodeChallengeMethod(t *testing.T) {
	srv, _, _ := setupAuthorizeServer(t)
	q := validAuthorizeQuery()
	q.Del("code_challenge_method")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_request")
}

func TestAuthorize_MissingState(t *testing.T) {
	srv, _, _ := setupAuthorizeServer(t)
	q := validAuthorizeQuery()
	q.Del("state")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_request")
}

func TestAuthorize_MissingScope(t *testing.T) {
	srv, _, _ := setupAuthorizeServer(t)
	q := validAuthorizeQuery()
	q.Del("scope")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_scope")
}

func TestAuthorize_ScopeWithoutOpenID(t *testing.T) {
	srv, _, _ := setupAuthorizeServer(t)
	q := validAuthorizeQuery()
	q.Set("scope", "email profile")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_scope")
}

// --- /authorize テスト: 未認証 → ログインリダイレクト ---

func TestAuthorize_UnauthenticatedRedirectsToLogin(t *testing.T) {
	srv, _, _ := setupAuthorizeServer(t)
	q := validAuthorizeQuery()

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, w.Code)
	}

	location := w.Header().Get("Location")
	if !strings.HasPrefix(location, "/login?redirect_to=") {
		t.Errorf("expected redirect to /login, got %q", location)
	}
	// redirect_to パラメータに元の /authorize URL が含まれるか
	if !strings.Contains(location, "authorize") {
		t.Errorf("expected redirect_to to contain 'authorize', got %q", location)
	}
}

// --- /authorize テスト: 認証済み → 認可コード発行 ---

func TestAuthorize_AuthenticatedIssuesCode(t *testing.T) {
	srv, sm, st := setupAuthorizeServer(t)
	q := validAuthorizeQuery()
	cookies := issueTestSession(t, sm)

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected %d, got %d; body: %s", http.StatusFound, w.Code, w.Body.String())
	}

	location := w.Header().Get("Location")
	locURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse Location header: %v", err)
	}

	// redirect_uri にリダイレクトされる
	if !strings.HasPrefix(location, "http://localhost:3000/callback?") {
		t.Errorf("expected redirect to redirect_uri, got %q", location)
	}

	// code パラメータが存在する（64文字の hex）
	code := locURL.Query().Get("code")
	if code == "" {
		t.Fatal("expected 'code' parameter in redirect URL")
	}
	if len(code) != 64 {
		t.Errorf("expected code length 64 (32 bytes hex), got %d", len(code))
	}

	// state パラメータが返される
	returnedState := locURL.Query().Get("state")
	if returnedState != "random-state-value" {
		t.Errorf("expected state %q, got %q", "random-state-value", returnedState)
	}

	// Store に認可コードが保存されている
	ctx := context.Background()
	authCode, err := st.GetAuthCode(ctx, code)
	if err != nil {
		t.Fatalf("GetAuthCode: %v", err)
	}
	if authCode == nil {
		t.Fatal("auth code not found in store")
	}
	if authCode.ClientID != "test-oauth-client" {
		t.Errorf("expected ClientID %q, got %q", "test-oauth-client", authCode.ClientID)
	}
	if authCode.RedirectURI != "http://localhost:3000/callback" {
		t.Errorf("expected RedirectURI %q, got %q", "http://localhost:3000/callback", authCode.RedirectURI)
	}
	if authCode.CodeChallenge != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Errorf("expected CodeChallenge preserved, got %q", authCode.CodeChallenge)
	}
	if authCode.CodeChallengeMethod != "S256" {
		t.Errorf("expected CodeChallengeMethod 'S256', got %q", authCode.CodeChallengeMethod)
	}
	if authCode.User == nil || authCode.User.Email != "test@example.com" {
		t.Errorf("expected user email %q, got %v", "test@example.com", authCode.User)
	}
	if authCode.Used {
		t.Error("expected Used=false for new auth code")
	}
	if len(authCode.Scopes) != 1 || authCode.Scopes[0] != "openid" {
		t.Errorf("expected scopes [openid], got %v", authCode.Scopes)
	}
}

func TestAuthorize_AuthenticatedMultipleScopes(t *testing.T) {
	srv, sm, st := setupAuthorizeServer(t)
	q := validAuthorizeQuery()
	q.Set("scope", "openid email profile")
	cookies := issueTestSession(t, sm)

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, w.Code)
	}

	locURL, _ := url.Parse(w.Header().Get("Location"))
	code := locURL.Query().Get("code")

	authCode, _ := st.GetAuthCode(context.Background(), code)
	if authCode == nil {
		t.Fatal("auth code not found in store")
	}
	if len(authCode.Scopes) != 3 {
		t.Errorf("expected 3 scopes, got %d: %v", len(authCode.Scopes), authCode.Scopes)
	}
}

func TestAuthorize_ExpiredSessionRedirectsToLogin(t *testing.T) {
	srv, sm, st := setupAuthorizeServer(t)
	q := validAuthorizeQuery()

	// セッションを発行してから Store で有効期限を過去に設定
	ctx := context.Background()
	user := &User{
		Email:   "test@example.com",
		Name:    "Test User",
		Subject: "sub-123",
		Issuer:  "https://accounts.google.com",
	}
	sess, err := sm.IssueSession(ctx, user, "https://accounts.google.com", "raw-id-token")
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	// セッションの有効期限を過去に設定
	sess.ExpiresAt = time.Now().Add(-time.Hour)
	_ = st.SetSession(ctx, sess.ID, sess, time.Hour)

	wCookie := httptest.NewRecorder()
	if err := sm.SetCookie(wCookie, sess.ID); err != nil {
		t.Fatalf("SetCookie: %v", err)
	}
	cookies := wCookie.Result().Cookies()

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, w.Code)
	}

	location := w.Header().Get("Location")
	if !strings.HasPrefix(location, "/login?redirect_to=") {
		t.Errorf("expected redirect to /login for expired session, got %q", location)
	}
}

func TestAuthorize_WithPathPrefix(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	st := newTestMemoryStore()
	cfg := Config{
		Providers: []OIDCProvider{
			{
				Issuer:       "https://accounts.google.com",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		},
		ExternalURL:  "http://localhost:8080",
		CookieSecret: bytes.Repeat([]byte("a"), 32),
		PathPrefix:   "/auth",
		Store:        st,
		OAuth: &OAuthConfig{
			SigningKey:          privateKey,
			ClientID:            "test-oauth-client",
			AllowedRedirectURIs: []string{"http://localhost:3000/callback"},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate() failed: %v", err)
	}

	sm, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("NewSessionManager() failed: %v", err)
	}

	srv, err := NewOAuthServer(cfg, st, sm)
	if err != nil {
		t.Fatalf("NewOAuthServer() failed: %v", err)
	}

	q := validAuthorizeQuery()

	// 未認証: /auth/login へリダイレクト
	req := httptest.NewRequest(http.MethodGet, "/auth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, w.Code)
	}

	location := w.Header().Get("Location")
	if !strings.HasPrefix(location, "/auth/login?redirect_to=") {
		t.Errorf("expected redirect to /auth/login, got %q", location)
	}
}

func TestAuthorize_AllowedRedirectURIs_Localhost(t *testing.T) {
	// AllowedRedirectURIs が空の場合、localhost のみ許可される
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	st := newTestMemoryStore()
	cfg := Config{
		Providers: []OIDCProvider{
			{
				Issuer:       "https://accounts.google.com",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		},
		ExternalURL:  "http://localhost:8080",
		CookieSecret: bytes.Repeat([]byte("a"), 32),
		Store:        st,
		OAuth: &OAuthConfig{
			SigningKey: privateKey,
			// ClientID is empty - accepts any
			// AllowedRedirectURIs is empty - only localhost
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate() failed: %v", err)
	}

	sm, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("NewSessionManager() failed: %v", err)
	}

	srv, err := NewOAuthServer(cfg, st, sm)
	if err != nil {
		t.Fatalf("NewOAuthServer() failed: %v", err)
	}

	// localhost は許可される
	q := validAuthorizeQuery()
	q.Set("client_id", "any-client") // ClientID が空なので任意の client_id が許可される
	q.Set("redirect_uri", "http://localhost:3000/callback")
	cookies := issueTestSession(t, sm)

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected %d for localhost redirect_uri, got %d; body: %s", http.StatusFound, w.Code, w.Body.String())
	}

	// 非 localhost は拒否される
	q2 := validAuthorizeQuery()
	q2.Set("client_id", "any-client")
	q2.Set("redirect_uri", "https://evil.example.com/callback")

	req2 := httptest.NewRequest(http.MethodGet, "/authorize?"+q2.Encode(), nil)
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req2)

	if w2.Code != http.StatusBadRequest {
		t.Fatalf("expected %d for non-localhost redirect_uri, got %d", http.StatusBadRequest, w2.Code)
	}
}

// --- テスト用ヘルパー: error レスポンス検証 ---

func assertErrorResponse(t *testing.T, w *httptest.ResponseRecorder, expectedError string) {
	t.Helper()
	var errResp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp["error"] != expectedError {
		t.Errorf("expected error %q, got %q", expectedError, errResp["error"])
	}
}

// --- 既存テスト用ヘルパー ---

func assertStringSliceField(t *testing.T, m map[string]any, key string, expected []string) {
	t.Helper()
	val, ok := m[key]
	if !ok {
		t.Errorf("missing field %q", key)
		return
	}
	arr, ok := val.([]any)
	if !ok {
		t.Errorf("field %q is not an array: %v", key, val)
		return
	}
	if len(arr) != len(expected) {
		t.Errorf("field %q: expected %d elements, got %d", key, len(expected), len(arr))
		return
	}
	for i, v := range arr {
		str, ok := v.(string)
		if !ok {
			t.Errorf("field %q[%d] is not a string: %v", key, i, v)
			continue
		}
		if str != expected[i] {
			t.Errorf("field %q[%d]: expected %q, got %q", key, i, expected[i], str)
		}
	}
}

// --- /token エンドポイント テスト ---

// setupTokenServer はテスト用の OAuthServer を構築し、認可コードを事前に Store に保存する。
// code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" (RFC 7636 Appendix B)
// code_challenge = S256(code_verifier) = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
func setupTokenServer(t *testing.T) (*OAuthServer, *testMemoryStore, string) {
	t.Helper()
	srv, _, st := setupAuthorizeServer(t)

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := S256Challenge(codeVerifier)

	code := "test-auth-code-1234567890abcdef"

	authCodeData := &AuthCodeData{
		Code:                code,
		ClientID:            "test-oauth-client",
		RedirectURI:         "http://localhost:3000/callback",
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		Scopes:              []string{"openid"},
		User: &User{
			Email:   "test@example.com",
			Name:    "Test User",
			Subject: "sub-123",
			Issuer:  "https://accounts.google.com",
		},
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Used:      false,
	}

	ctx := context.Background()
	if err := st.SetAuthCode(ctx, code, authCodeData, 5*time.Minute); err != nil {
		t.Fatalf("SetAuthCode: %v", err)
	}

	return srv, st, code
}

// validTokenForm は正常な /token リクエストのフォームデータを返す。
func validTokenForm(code string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"client_id":     {"test-oauth-client"},
		"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
	}
}

func TestToken_Success(t *testing.T) {
	srv, st, code := setupTokenServer(t)
	form := validTokenForm(code)

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d; body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	// Content-Type 検証
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	// Cache-Control 検証
	cc := w.Header().Get("Cache-Control")
	if cc != "no-store" {
		t.Errorf("expected Cache-Control no-store, got %q", cc)
	}

	// レスポンス JSON パース
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// access_token が存在する
	accessToken, ok := resp["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatal("expected non-empty access_token in response")
	}

	// token_type = Bearer
	tokenType, ok := resp["token_type"].(string)
	if !ok || tokenType != "Bearer" {
		t.Errorf("expected token_type Bearer, got %q", tokenType)
	}

	// expires_in = 3600
	expiresIn, ok := resp["expires_in"].(float64)
	if !ok || expiresIn != 3600 {
		t.Errorf("expected expires_in 3600, got %v", resp["expires_in"])
	}

	// JWT を検証: パースして claims を確認
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"ES256"}))
	token, err := parser.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		return &srv.privateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse JWT: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("failed to extract JWT claims")
	}

	// claims 検証
	if claims["iss"] != "http://localhost:8080" {
		t.Errorf("expected iss 'http://localhost:8080', got %v", claims["iss"])
	}
	if claims["sub"] != "sub-123" {
		t.Errorf("expected sub 'sub-123', got %v", claims["sub"])
	}
	if claims["email"] != "test@example.com" {
		t.Errorf("expected email 'test@example.com', got %v", claims["email"])
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		t.Error("expected non-empty jti claim")
	}

	// Store に AccessTokenData が保存されている
	ctx := context.Background()
	tokenData, err := st.GetAccessToken(ctx, jti)
	if err != nil {
		t.Fatalf("GetAccessToken: %v", err)
	}
	if tokenData == nil {
		t.Fatal("access token not found in store")
	}
	if tokenData.Email != "test@example.com" {
		t.Errorf("expected email %q, got %q", "test@example.com", tokenData.Email)
	}
	if tokenData.ClientID != "test-oauth-client" {
		t.Errorf("expected ClientID %q, got %q", "test-oauth-client", tokenData.ClientID)
	}
	if tokenData.Revoked {
		t.Error("expected Revoked=false for new token")
	}

	// 認可コードが Used=true にマークされている
	authCode, _ := st.GetAuthCode(ctx, code)
	if authCode == nil {
		t.Fatal("auth code should still exist in store (marked as used)")
	}
	if !authCode.Used {
		t.Error("expected auth code Used=true after token exchange")
	}
}

func TestToken_MethodNotAllowed(t *testing.T) {
	srv, _, _ := setupTokenServer(t)

	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestToken_WrongContentType(t *testing.T) {
	srv, _, code := setupTokenServer(t)
	form := validTokenForm(code)

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_request")
}

func TestToken_UnsupportedGrantType(t *testing.T) {
	srv, _, code := setupTokenServer(t)
	form := validTokenForm(code)
	form.Set("grant_type", "client_credentials")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "unsupported_grant_type")
}

func TestToken_MissingCode(t *testing.T) {
	srv, _, _ := setupTokenServer(t)
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"client_id":     {"test-oauth-client"},
		"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_request")
}

func TestToken_MissingCodeVerifier(t *testing.T) {
	srv, _, code := setupTokenServer(t)
	form := validTokenForm(code)
	form.Del("code_verifier")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_request")
}

func TestToken_InvalidCode(t *testing.T) {
	srv, _, _ := setupTokenServer(t)
	form := validTokenForm("nonexistent-code")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_grant")
}

func TestToken_RedirectURIMismatch(t *testing.T) {
	srv, _, code := setupTokenServer(t)
	form := validTokenForm(code)
	form.Set("redirect_uri", "https://evil.example.com/callback")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_grant")
}

func TestToken_ClientIDMismatch(t *testing.T) {
	srv, _, code := setupTokenServer(t)
	form := validTokenForm(code)
	form.Set("client_id", "wrong-client")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_grant")
}

func TestToken_PKCEVerificationFailed(t *testing.T) {
	srv, _, code := setupTokenServer(t)
	form := validTokenForm(code)
	form.Set("code_verifier", "wrong-verifier-value")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_grant")
}

func TestToken_DoubleUse(t *testing.T) {
	srv, st, code := setupTokenServer(t)

	// 1回目: 成功
	form1 := validTokenForm(code)
	req1 := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form1.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w1 := httptest.NewRecorder()
	srv.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("first token request: expected %d, got %d; body: %s", http.StatusOK, w1.Code, w1.Body.String())
	}

	// 1回目のレスポンスからトークンの jti を取得（Store に保存されているか確認用）
	var resp1 map[string]any
	if err := json.NewDecoder(w1.Body).Decode(&resp1); err != nil {
		t.Fatalf("failed to decode first response: %v", err)
	}
	accessToken1 := resp1["access_token"].(string)

	// JWT から jti を取得
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token1, _, err := parser.ParseUnverified(accessToken1, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("failed to parse first token: %v", err)
	}
	jti1 := token1.Claims.(jwt.MapClaims)["jti"].(string)

	// 1回目のトークンが Store にあることを確認
	ctx := context.Background()
	tokenData, _ := st.GetAccessToken(ctx, jti1)
	if tokenData == nil {
		t.Fatal("first token should exist in store")
	}

	// 2回目: 二重使用 → invalid_grant
	form2 := validTokenForm(code)
	req2 := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req2)

	if w2.Code != http.StatusBadRequest {
		t.Fatalf("second token request: expected %d, got %d; body: %s", http.StatusBadRequest, w2.Code, w2.Body.String())
	}
	assertErrorResponse(t, w2, "invalid_grant")
}

func TestToken_ExpiredCode(t *testing.T) {
	srv, st, _ := setupTokenServer(t)

	// 有効期限切れの認可コードを作成
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := S256Challenge(codeVerifier)
	expiredCode := "expired-auth-code-1234567890"

	authCodeData := &AuthCodeData{
		Code:                expiredCode,
		ClientID:            "test-oauth-client",
		RedirectURI:         "http://localhost:3000/callback",
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		Scopes:              []string{"openid"},
		User: &User{
			Email:   "test@example.com",
			Name:    "Test User",
			Subject: "sub-123",
			Issuer:  "https://accounts.google.com",
		},
		CreatedAt: time.Now().Add(-10 * time.Minute),
		ExpiresAt: time.Now().Add(-5 * time.Minute), // 5分前に有効期限切れ
		Used:      false,
	}

	ctx := context.Background()
	if err := st.SetAuthCode(ctx, expiredCode, authCodeData, 5*time.Minute); err != nil {
		t.Fatalf("SetAuthCode: %v", err)
	}

	form := validTokenForm(expiredCode)
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d; body: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
	assertErrorResponse(t, w, "invalid_grant")
}

func TestToken_WithPathPrefix(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	st := newTestMemoryStore()
	cfg := Config{
		Providers: []OIDCProvider{
			{
				Issuer:       "https://accounts.google.com",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		},
		ExternalURL:  "http://localhost:8080",
		CookieSecret: bytes.Repeat([]byte("a"), 32),
		PathPrefix:   "/auth",
		Store:        st,
		OAuth: &OAuthConfig{
			SigningKey:          privateKey,
			ClientID:            "test-oauth-client",
			AllowedRedirectURIs: []string{"http://localhost:3000/callback"},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate() failed: %v", err)
	}

	srv, err := NewOAuthServer(cfg, st, nil)
	if err != nil {
		t.Fatalf("NewOAuthServer() failed: %v", err)
	}

	// 認可コードを Store に保存
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := S256Challenge(codeVerifier)
	code := "test-auth-code-with-prefix"

	authCodeData := &AuthCodeData{
		Code:                code,
		ClientID:            "test-oauth-client",
		RedirectURI:         "http://localhost:3000/callback",
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		Scopes:              []string{"openid"},
		User: &User{
			Email:   "test@example.com",
			Name:    "Test User",
			Subject: "sub-123",
			Issuer:  "https://accounts.google.com",
		},
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Used:      false,
	}

	ctx := context.Background()
	if err := st.SetAuthCode(ctx, code, authCodeData, 5*time.Minute); err != nil {
		t.Fatalf("SetAuthCode: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"client_id":     {"test-oauth-client"},
		"code_verifier": {codeVerifier},
	}

	// PathPrefix 付き /auth/token
	req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d; body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if _, ok := resp["access_token"].(string); !ok {
		t.Error("expected access_token in response")
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("expected token_type Bearer, got %v", resp["token_type"])
	}
}

// --- Register (Dynamic Client Registration: RFC 7591) テスト ---

func TestRegister_Success(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "")

	reqBody := map[string]any{
		"redirect_uris": []string{"https://app.example.com/callback"},
		"client_name":   "My App",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// client_id が生成されている
	clientID, ok := resp["client_id"].(string)
	if !ok || clientID == "" {
		t.Error("expected non-empty client_id")
	}

	// client_name が返却されている
	if resp["client_name"] != "My App" {
		t.Errorf("expected client_name 'My App', got %v", resp["client_name"])
	}

	// redirect_uris が返却されている
	uris, ok := resp["redirect_uris"].([]any)
	if !ok || len(uris) != 1 || uris[0] != "https://app.example.com/callback" {
		t.Errorf("unexpected redirect_uris: %v", resp["redirect_uris"])
	}

	// デフォルト値が設定されている
	if resp["token_endpoint_auth_method"] != "none" {
		t.Errorf("expected token_endpoint_auth_method 'none', got %v", resp["token_endpoint_auth_method"])
	}

	grantTypes, ok := resp["grant_types"].([]any)
	if !ok || len(grantTypes) != 2 || grantTypes[0] != "authorization_code" || grantTypes[1] != "refresh_token" {
		t.Errorf("unexpected grant_types: %v", resp["grant_types"])
	}

	responseTypes, ok := resp["response_types"].([]any)
	if !ok || len(responseTypes) != 1 || responseTypes[0] != "code" {
		t.Errorf("unexpected response_types: %v", resp["response_types"])
	}
}

func TestRegister_StoresPersistsClient(t *testing.T) {
	st := newTestMemoryStore()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cfg := Config{
		Providers: []OIDCProvider{
			{Issuer: "https://accounts.google.com", ClientID: "x", ClientSecret: "y"},
		},
		ExternalURL:  "http://localhost:8080",
		CookieSecret: []byte("test-cookie-secret-32-bytes-long!"),
		Store:        st,
		OAuth:        &OAuthConfig{SigningKey: privateKey},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate() failed: %v", err)
	}

	srv, err := NewOAuthServer(cfg, st, nil)
	if err != nil {
		t.Fatalf("NewOAuthServer() failed: %v", err)
	}

	reqBody := map[string]any{
		"redirect_uris": []string{"https://app.example.com/callback"},
		"client_name":   "Stored App",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	clientID := resp["client_id"].(string)

	// Store から取得できることを確認
	stored, err := st.GetClient(context.Background(), clientID)
	if err != nil {
		t.Fatalf("GetClient error: %v", err)
	}
	if stored == nil {
		t.Fatal("expected client to be stored, got nil")
	}
	if stored.ClientName != "Stored App" {
		t.Errorf("expected client_name 'Stored App', got %q", stored.ClientName)
	}
	if len(stored.RedirectURIs) != 1 || stored.RedirectURIs[0] != "https://app.example.com/callback" {
		t.Errorf("unexpected redirect_uris: %v", stored.RedirectURIs)
	}
}

func TestRegister_MethodNotAllowed(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "")

	req := httptest.NewRequest(http.MethodGet, "/register", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestRegister_WrongContentType(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "")

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRegister_MissingRedirectURIs(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "")

	reqBody := map[string]any{
		"client_name": "No URIs",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegister_EmptyRedirectURIs(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "")

	reqBody := map[string]any{
		"redirect_uris": []string{},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegister_InvalidRedirectURI(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "")

	reqBody := map[string]any{
		"redirect_uris": []string{"not a valid uri"},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegister_InvalidJSON(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "")

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegister_WithPathPrefix(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "/auth")

	reqBody := map[string]any{
		"redirect_uris": []string{"https://app.example.com/callback"},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegister_MultipleRedirectURIs(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "")

	reqBody := map[string]any{
		"redirect_uris": []string{
			"https://app.example.com/callback",
			"https://app.example.com/callback2",
		},
		"client_name": "Multi URI App",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	uris, ok := resp["redirect_uris"].([]any)
	if !ok || len(uris) != 2 {
		t.Errorf("expected 2 redirect_uris, got %v", resp["redirect_uris"])
	}
}

func TestRegister_WithScope(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "")

	reqBody := map[string]any{
		"redirect_uris": []string{"https://app.example.com/callback"},
		"scope":         "openid email profile",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["scope"] != "openid email profile" {
		t.Errorf("expected scope 'openid email profile', got %v", resp["scope"])
	}
}

// TestAuthorize_DynamicClient は動的登録クライアントが /authorize を利用できることを確認する。
func TestAuthorize_DynamicClient(t *testing.T) {
	st := newTestMemoryStore()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cfg := Config{
		Providers: []OIDCProvider{
			{Issuer: "https://accounts.google.com", ClientID: "x", ClientSecret: "y"},
		},
		ExternalURL:  "http://localhost:8080",
		CookieSecret: []byte("test-cookie-secret-32-bytes-long!"),
		Store:        st,
		OAuth:        &OAuthConfig{SigningKey: privateKey},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate() failed: %v", err)
	}

	sm, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	srv, err := NewOAuthServer(cfg, st, sm)
	if err != nil {
		t.Fatalf("NewOAuthServer() failed: %v", err)
	}

	// 1. まず /register でクライアントを登録
	registerBody := map[string]any{
		"redirect_uris": []string{"https://app.example.com/callback"},
		"client_name":   "Dynamic Client",
	}
	body, _ := json.Marshal(registerBody)

	regReq := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	srv.ServeHTTP(regW, regReq)

	if regW.Code != http.StatusCreated {
		t.Fatalf("register expected 201, got %d", regW.Code)
	}

	var regResp map[string]any
	_ = json.NewDecoder(regW.Body).Decode(&regResp)
	dynamicClientID := regResp["client_id"].(string)

	// 2. セッションを作成してログイン状態にする
	sessionCookies := issueTestSession(t, sm)

	// 3. /authorize に動的クライアント ID でアクセス
	authorizeURL := "/authorize?response_type=code&client_id=" + dynamicClientID +
		"&redirect_uri=" + url.QueryEscape("https://app.example.com/callback") +
		"&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" +
		"&code_challenge_method=S256&state=test-state&scope=openid"

	authReq := httptest.NewRequest(http.MethodGet, authorizeURL, nil)
	for _, c := range sessionCookies {
		authReq.AddCookie(c)
	}
	authW := httptest.NewRecorder()
	srv.ServeHTTP(authW, authReq)

	// 認証済みなので 302 リダイレクトが期待される
	if authW.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", authW.Code, authW.Body.String())
	}

	loc := authW.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://app.example.com/callback") {
		t.Errorf("expected redirect to app callback, got %s", loc)
	}
}

// --- リフレッシュトークン関連テスト (T1〜T15) ---

// setupTokenServerWithRefreshToken は authorization_code フローを完走し、
// refresh_token 付きレスポンスを得るヘルパー。
// 返り値: (*OAuthServer, *testMemoryStore, refreshToken string, accessToken string)
func setupTokenServerWithRefreshToken(t *testing.T) (*OAuthServer, *testMemoryStore, string, string) {
	t.Helper()
	srv, st, code := setupTokenServer(t)

	form := validTokenForm(code)
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("authorization_code exchange failed: %d %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}

	rt, ok := resp["refresh_token"].(string)
	if !ok || rt == "" {
		t.Fatal("refresh_token not found in authorization_code response")
	}

	at, _ := resp["access_token"].(string)
	return srv, st, rt, at
}

// T2: authorization_code の成功フローで refresh_token が返される
func TestToken_AuthCode_ReturnsRefreshToken(t *testing.T) {
	srv, _, code := setupTokenServer(t)
	form := validTokenForm(code)

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d; body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	rt, ok := resp["refresh_token"].(string)
	if !ok || rt == "" {
		t.Error("expected non-empty refresh_token in authorization_code response")
	}

	// access_token は従来通り存在する
	if _, ok := resp["access_token"].(string); !ok {
		t.Error("expected access_token in response")
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("expected token_type Bearer, got %v", resp["token_type"])
	}
}

// T3: Discovery の grant_types_supported に refresh_token が含まれる
func TestOAuthServer_Metadata_GrantTypesIncludeRefreshToken(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var meta map[string]any
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("failed to decode metadata JSON: %v", err)
	}

	assertStringSliceField(t, meta, "grant_types_supported", []string{"authorization_code", "refresh_token"})
}

// T4: DCR 応答の grant_types に refresh_token が含まれる
func TestRegister_GrantTypesIncludeRefreshToken(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "")

	reqBody := map[string]any{
		"redirect_uris": []string{"https://app.example.com/callback"},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	grantTypes, ok := resp["grant_types"].([]any)
	if !ok {
		t.Fatal("grant_types is not an array")
	}
	if len(grantTypes) != 2 {
		t.Fatalf("expected 2 grant_types, got %d: %v", len(grantTypes), grantTypes)
	}
	if grantTypes[0] != "authorization_code" || grantTypes[1] != "refresh_token" {
		t.Errorf("unexpected grant_types: %v", grantTypes)
	}
}

// T1: refresh_token grant で新 access_token + 異なる refresh_token が返される
func TestToken_RefreshGrant_Success(t *testing.T) {
	srv, _, oldRT, _ := setupTokenServerWithRefreshToken(t)

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {oldRT},
		"client_id":     {"test-oauth-client"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d; body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	newRT, ok := resp["refresh_token"].(string)
	if !ok || newRT == "" {
		t.Fatal("expected new refresh_token in response")
	}
	if newRT == oldRT {
		t.Error("new refresh_token should differ from old refresh_token")
	}

	newAT, ok := resp["access_token"].(string)
	if !ok || newAT == "" {
		t.Fatal("expected new access_token in response")
	}

	if resp["token_type"] != "Bearer" {
		t.Errorf("expected token_type Bearer, got %v", resp["token_type"])
	}

	if _, ok := resp["expires_in"].(float64); !ok {
		t.Error("expected expires_in in response")
	}
}

// T5: refresh 成功後の Store 状態を検証
func TestToken_RefreshGrant_StoreState(t *testing.T) {
	srv, st, oldRT, _ := setupTokenServerWithRefreshToken(t)

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {oldRT},
		"client_id":     {"test-oauth-client"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d; body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	newRT := resp["refresh_token"].(string)

	ctx := context.Background()

	// 旧 refresh_token は GetRefreshToken で取得可能で Used=true
	oldData, err := st.GetRefreshToken(ctx, oldRT)
	if err != nil {
		t.Fatalf("GetRefreshToken(old): %v", err)
	}
	if oldData == nil {
		t.Fatal("old refresh_token should still exist in store")
	}
	if !oldData.Used {
		t.Error("old refresh_token should have Used=true")
	}

	// 新 refresh_token は Used=false で存在する
	newData, err := st.GetRefreshToken(ctx, newRT)
	if err != nil {
		t.Fatalf("GetRefreshToken(new): %v", err)
	}
	if newData == nil {
		t.Fatal("new refresh_token should exist in store")
	}
	if newData.Used {
		t.Error("new refresh_token should have Used=false")
	}

	// 両者の FamilyID が同一
	if oldData.FamilyID != newData.FamilyID {
		t.Errorf("expected same FamilyID, old=%q new=%q", oldData.FamilyID, newData.FamilyID)
	}
}

// T6: refresh_token パラメータ欠損 → 400 invalid_request
func TestToken_RefreshGrant_MissingRefreshToken(t *testing.T) {
	srv, _, _, _ := setupTokenServerWithRefreshToken(t)

	form := url.Values{
		"grant_type": {"refresh_token"},
		"client_id":  {"test-oauth-client"},
		// refresh_token は省略
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_request")
}

// T7: 未登録 refresh_token → 400 invalid_grant
func TestToken_RefreshGrant_UnknownRefreshToken(t *testing.T) {
	srv, _, _, _ := setupTokenServerWithRefreshToken(t)

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"nonexistent-token"},
		"client_id":     {"test-oauth-client"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	assertErrorResponse(t, w, "invalid_grant")
}

// T8: 同一 refresh_token を 2 回使用（replay） → 1回目 200、2回目 400 + tombstone
func TestToken_RefreshGrant_Replay(t *testing.T) {
	srv, st, oldRT, _ := setupTokenServerWithRefreshToken(t)

	sendRefresh := func() *httptest.ResponseRecorder {
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {oldRT},
			"client_id":     {"test-oauth-client"},
		}
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w
	}

	// 1回目: 成功
	w1 := sendRefresh()
	if w1.Code != http.StatusOK {
		t.Fatalf("1st refresh: expected %d, got %d; body: %s", http.StatusOK, w1.Code, w1.Body.String())
	}

	// 2回目: replay → invalid_grant
	w2 := sendRefresh()
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("2nd refresh (replay): expected %d, got %d; body: %s", http.StatusBadRequest, w2.Code, w2.Body.String())
	}
	assertErrorResponse(t, w2, "invalid_grant")

	// familyID を取得して tombstone が書き込まれているか確認
	ctx := context.Background()
	oldData, err := st.GetRefreshToken(ctx, oldRT)
	if err != nil {
		t.Fatalf("GetRefreshToken: %v", err)
	}
	if oldData == nil {
		t.Fatal("old refresh_token should still exist in store")
	}
	revoked, err := st.IsFamilyRevoked(ctx, oldData.FamilyID)
	if err != nil {
		t.Fatalf("IsFamilyRevoked: %v", err)
	}
	if !revoked {
		t.Error("family should be tombstoned after replay detection")
	}
}

// T8b: T8 の後、同 family から派生した別の（live な）refresh_token を使用 → invalid_grant
func TestToken_RefreshGrant_ReplayFamilyRevocation(t *testing.T) {
	srv, st, oldRT, _ := setupTokenServerWithRefreshToken(t)

	// 1回目の refresh で新 RT を取得
	form1 := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {oldRT},
		"client_id":     {"test-oauth-client"},
	}
	req1 := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form1.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w1 := httptest.NewRecorder()
	srv.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("1st refresh failed: %d %s", w1.Code, w1.Body.String())
	}
	var resp1 map[string]any
	_ = json.NewDecoder(w1.Body).Decode(&resp1)
	newRT := resp1["refresh_token"].(string)

	// 旧 RT を再度使用 (replay) → tombstone が書き込まれる
	form2 := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {oldRT},
		"client_id":     {"test-oauth-client"},
	}
	req2 := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req2)
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("replay should fail: %d %s", w2.Code, w2.Body.String())
	}

	// tombstone が書き込まれていることを確認
	ctx := context.Background()
	oldData, _ := st.GetRefreshToken(ctx, oldRT)
	if oldData != nil {
		revoked, _ := st.IsFamilyRevoked(ctx, oldData.FamilyID)
		if !revoked {
			t.Fatal("expected family to be tombstoned")
		}
	}

	// 同一 family の新 RT を使用 → tombstone で invalid_grant
	form3 := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {newRT},
		"client_id":     {"test-oauth-client"},
	}
	req3 := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form3.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w3 := httptest.NewRecorder()
	srv.ServeHTTP(w3, req3)
	if w3.Code != http.StatusBadRequest {
		t.Fatalf("tombstoned family RT should fail: %d %s", w3.Code, w3.Body.String())
	}
	assertErrorResponse(t, w3, "invalid_grant")
}

// T9: RefreshTokenTTL=1ms で待機後に使用 → invalid_grant
func TestToken_RefreshGrant_Expired(t *testing.T) {
	// TTL を 1ms に設定したサーバーを作成
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	st := newTestMemoryStore()
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := S256Challenge(codeVerifier)
	code := "test-auth-code-ttl-test"
	authCodeData := &AuthCodeData{
		Code:                code,
		ClientID:            "test-oauth-client",
		RedirectURI:         "http://localhost:3000/callback",
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		Scopes:              []string{"openid"},
		User: &User{
			Email:   "test@example.com",
			Name:    "Test User",
			Subject: "sub-123",
			Issuer:  "https://accounts.google.com",
		},
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Used:      false,
	}
	ctx := context.Background()
	if err := st.SetAuthCode(ctx, code, authCodeData, 5*time.Minute); err != nil {
		t.Fatalf("SetAuthCode: %v", err)
	}

	cfg := Config{
		Providers: []OIDCProvider{
			{
				Issuer:       "https://accounts.google.com",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		},
		ExternalURL:     "http://localhost:8080",
		CookieSecret:    bytes.Repeat([]byte("a"), 32),
		Store:           st,
		RefreshTokenTTL: 1 * time.Millisecond, // 超短い TTL
		OAuth: &OAuthConfig{
			SigningKey:          privateKey,
			ClientID:            "test-oauth-client",
			AllowedRedirectURIs: []string{"http://localhost:3000/callback"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate(): %v", err)
	}
	srv, err := NewOAuthServer(cfg, st, nil)
	if err != nil {
		t.Fatalf("NewOAuthServer(): %v", err)
	}

	// まず authorization_code で refresh_token を取得
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"client_id":     {"test-oauth-client"},
		"code_verifier": {codeVerifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("authorization_code exchange failed: %d %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	rt := resp["refresh_token"].(string)

	// TTL が切れるまで待機
	time.Sleep(5 * time.Millisecond)

	// 期限切れ refresh_token を使用 → invalid_grant
	form2 := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {"test-oauth-client"},
	}
	req2 := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req2)

	if w2.Code != http.StatusBadRequest {
		t.Fatalf("expected %d for expired RT, got %d; body: %s", http.StatusBadRequest, w2.Code, w2.Body.String())
	}
	assertErrorResponse(t, w2, "invalid_grant")
}

// T10: client_id 不一致 → 400 invalid_grant
func TestToken_RefreshGrant_ClientIDMismatch(t *testing.T) {
	srv, _, rt, _ := setupTokenServerWithRefreshToken(t)

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {"wrong-client-id"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d; body: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
	assertErrorResponse(t, w, "invalid_grant")
}

// T11: authorization_code リクエストに refresh_token パラメータ混在 → T2 通り動作
func TestToken_AuthCode_IgnoresRefreshTokenParam(t *testing.T) {
	srv, _, code := setupTokenServer(t)
	form := validTokenForm(code)
	form.Set("refresh_token", "some-ignored-token")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d; body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// 正常に access_token + refresh_token が返される
	if _, ok := resp["access_token"].(string); !ok {
		t.Error("expected access_token in response")
	}
	if _, ok := resp["refresh_token"].(string); !ok {
		t.Error("expected refresh_token in response")
	}
}

// T12: 同一 refresh_token を 2 goroutine で同時送信 → 片方 200、片方 400
func TestToken_RefreshGrant_Concurrent(t *testing.T) {
	srv, _, rt, _ := setupTokenServerWithRefreshToken(t)

	type result struct {
		code int
		body string
	}

	results := make(chan result, 2)

	sendRefresh := func() {
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {rt},
			"client_id":     {"test-oauth-client"},
		}
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		results <- result{code: w.Code, body: w.Body.String()}
	}

	go sendRefresh()
	go sendRefresh()

	r1 := <-results
	r2 := <-results

	codes := []int{r1.code, r2.code}
	ok200 := 0
	ok400 := 0
	for _, c := range codes {
		if c == http.StatusOK {
			ok200++
		} else if c == http.StatusBadRequest {
			ok400++
		}
	}

	if ok200 != 1 || ok400 != 1 {
		t.Errorf("expected exactly 1 success and 1 failure, got %d x 200 and %d x 400 (bodies: %q, %q)",
			ok200, ok400, r1.body, r2.body)
	}
}

// T15: Config.AccessTokenTTL=30m → access_token の exp が 30 分
func TestToken_AccessTokenTTL_FromConfig(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	st := newTestMemoryStore()
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := S256Challenge(codeVerifier)
	code := "test-auth-code-ttl-30m"
	authCodeData := &AuthCodeData{
		Code:                code,
		ClientID:            "test-oauth-client",
		RedirectURI:         "http://localhost:3000/callback",
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		Scopes:              []string{"openid"},
		User: &User{
			Email:   "test@example.com",
			Name:    "Test User",
			Subject: "sub-123",
			Issuer:  "https://accounts.google.com",
		},
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Used:      false,
	}
	ctx := context.Background()
	if err := st.SetAuthCode(ctx, code, authCodeData, 5*time.Minute); err != nil {
		t.Fatalf("SetAuthCode: %v", err)
	}

	cfg := Config{
		Providers: []OIDCProvider{
			{
				Issuer:       "https://accounts.google.com",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		},
		ExternalURL:    "http://localhost:8080",
		CookieSecret:   bytes.Repeat([]byte("a"), 32),
		Store:          st,
		AccessTokenTTL: 30 * time.Minute,
		OAuth: &OAuthConfig{
			SigningKey:          privateKey,
			ClientID:            "test-oauth-client",
			AllowedRedirectURIs: []string{"http://localhost:3000/callback"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate(): %v", err)
	}
	srv, err := NewOAuthServer(cfg, st, nil)
	if err != nil {
		t.Fatalf("NewOAuthServer(): %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"client_id":     {"test-oauth-client"},
		"code_verifier": {codeVerifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d; body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// expires_in は 1800 (30分)
	expiresIn, ok := resp["expires_in"].(float64)
	if !ok {
		t.Fatalf("expected expires_in in response, got %T %v", resp["expires_in"], resp["expires_in"])
	}
	if expiresIn != 1800 {
		t.Errorf("expected expires_in 1800 (30 min), got %v", expiresIn)
	}

	// JWT の exp クレームを検証
	accessToken := resp["access_token"].(string)
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("failed to parse JWT: %v", err)
	}
	claims := token.Claims.(jwt.MapClaims)
	expNum, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("exp claim is not a number: %T %v", claims["exp"], claims["exp"])
	}
	iatNum, ok := claims["iat"].(float64)
	if !ok {
		t.Fatalf("iat claim is not a number: %T %v", claims["iat"], claims["iat"])
	}
	diff := expNum - iatNum
	if diff < 1799 || diff > 1801 {
		t.Errorf("expected exp - iat ≈ 1800 (30 min), got %.0f", diff)
	}

	// Store の AccessTokenData の ExpiresAt も 30 分になっていること
	jti, _ := claims["jti"].(string)
	tokenData, err := st.GetAccessToken(ctx, jti)
	if err != nil {
		t.Fatalf("GetAccessToken: %v", err)
	}
	if tokenData == nil {
		t.Fatal("access token not found in store")
	}
	storeTTL := tokenData.ExpiresAt.Sub(tokenData.IssuedAt)
	if storeTTL < 29*time.Minute || storeTTL > 31*time.Minute {
		t.Errorf("expected store TTL ≈ 30 min, got %v", storeTTL)
	}
}
