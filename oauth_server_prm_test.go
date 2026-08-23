package idproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// --- Protected Resource Metadata（RFC 9728）エンドポイントテスト ---

// assertProtectedResourceMetadata は PRM レスポンスが 200 / application/json で
// RFC 9728 のフィールドを備えることを検証する。
func assertProtectedResourceMetadata(t *testing.T, w *httptest.ResponseRecorder, externalURL string) {
	t.Helper()

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	var meta map[string]any
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("failed to decode protected resource metadata JSON: %v", err)
	}

	assertStringField(t, meta, "resource", externalURL)
	assertStringSliceField(t, meta, "authorization_servers", []string{externalURL})
	assertStringSliceField(t, meta, "scopes_supported", []string{"openid", "email", "profile"})
	assertStringSliceField(t, meta, "bearer_methods_supported", []string{"header"})
}

func TestOAuthServer_ProtectedResourceMetadata_NoPrefix(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	assertProtectedResourceMetadata(t, w, "http://localhost:8080")
}

// TestOAuthServer_ProtectedResourceMetadata_WithPathPrefix は PathPrefix が非空でも
// RFC 9728 が定める素のパスで PRM を提供し、PathPrefix 付きの互換 alias も
// 同一の JSON を返すことを検証する。
func TestOAuthServer_ProtectedResourceMetadata_WithPathPrefix(t *testing.T) {
	srv := setupOAuthServer(t, "https://example.com", "/auth")

	paths := []string{
		"/.well-known/oauth-protected-resource",      // RFC 9728 準拠の素パス
		"/auth/.well-known/oauth-protected-resource", // 既存 well-known 体系との互換 alias
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()

			srv.ServeHTTP(w, req)

			assertProtectedResourceMetadata(t, w, "https://example.com")
		})
	}
}

// TestOAuthServer_ProtectedResourceMetadata_PrefixSuffixedPathNotServed は
// resource identifier に path を持たない構成で RFC 上の根拠がない
// /.well-known/oauth-protected-resource{PathPrefix} 形式を提供しないことを検証する。
func TestOAuthServer_ProtectedResourceMetadata_PrefixSuffixedPathNotServed(t *testing.T) {
	srv := setupOAuthServer(t, "https://example.com", "/auth")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/auth", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestOAuthServer_ProtectedResourceMetadata_MethodNotAllowed(t *testing.T) {
	tests := []struct {
		name       string
		pathPrefix string
		path       string
	}{
		{"no prefix", "", "/.well-known/oauth-protected-resource"},
		{"bare path with prefix", "/auth", "/.well-known/oauth-protected-resource"},
		{"prefixed alias", "/auth", "/auth/.well-known/oauth-protected-resource"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := setupOAuthServer(t, "https://example.com", tt.pathPrefix)

			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			w := httptest.NewRecorder()

			srv.ServeHTTP(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
			}
		})
	}
}
