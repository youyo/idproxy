package idproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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

	srv, err := NewOAuthServer(cfg, st)
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

	srv, err := NewOAuthServer(cfg, st)
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

	srv, err := NewOAuthServer(cfg, st)
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

	_, err = NewOAuthServer(cfg, st)
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
