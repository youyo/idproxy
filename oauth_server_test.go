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
	assertStringSliceField(t, meta, "grant_types_supported", []string{"authorization_code"})
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
		"response_type":        {"code"},
		"client_id":            {"test-oauth-client"},
		"redirect_uri":         {"http://localhost:3000/callback"},
		"code_challenge":       {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"state":                {"random-state-value"},
		"scope":                {"openid"},
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
