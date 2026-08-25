package idproxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// newEchoUpstream は受信したリクエストを捕捉する upstream を起動する。
func newEchoUpstream(t *testing.T, got **http.Request) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clone := r.Clone(r.Context())
		*got = clone
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// クライアントが送った身元ヘッダーは upstream に届かないこと（upstream への認証バイパス防止）。
func TestNewReverseProxy_StripsClientIdentityHeaders(t *testing.T) {
	var got *http.Request
	upstream := newEchoUpstream(t, &got)
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://proxy.example/resource", nil)
	req.RemoteAddr = "203.0.113.9:12345"
	for _, name := range identityHeaderDenylist {
		req.Header.Set(name, "spoofed")
	}
	// 非正規表記で送られても net/http のパーサが正規化するため、
	// Header.Del（正規化して削除）で確実に落とせることを合わせて確認する。
	req.Header.Set("x-forwarded-user", "spoofed-lowercase")

	rec := httptest.NewRecorder()
	NewReverseProxy(target).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("proxy returned %d", rec.Code)
	}
	if got == nil {
		t.Fatal("upstream did not receive the request")
	}
	for _, name := range identityHeaderDenylist {
		if v := got.Header.Get(name); v != "" {
			t.Errorf("%s reached upstream with value %q", name, v)
		}
	}
}

// クライアントが前置した X-Forwarded-For は破棄され、実接続元だけが渡ること。
func TestNewReverseProxy_ReplacesForwardedFor(t *testing.T) {
	var got *http.Request
	upstream := newEchoUpstream(t, &got)
	target, _ := url.Parse(upstream.URL)

	req := httptest.NewRequest(http.MethodGet, "http://proxy.example/resource", nil)
	req.RemoteAddr = "203.0.113.9:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.1")

	rec := httptest.NewRecorder()
	NewReverseProxy(target).ServeHTTP(rec, req)

	if got == nil {
		t.Fatal("upstream did not receive the request")
	}
	xff := got.Header.Get("X-Forwarded-For")
	if strings.Contains(xff, "10.0.0.1") {
		t.Errorf("client-supplied X-Forwarded-For survived: %q", xff)
	}
	if xff != "203.0.113.9" {
		t.Errorf("X-Forwarded-For = %q, want %q", xff, "203.0.113.9")
	}
}

// Host はクライアント指定値ではなく upstream のものになること。
func TestNewReverseProxy_SetsUpstreamHost(t *testing.T) {
	var got *http.Request
	upstream := newEchoUpstream(t, &got)
	target, _ := url.Parse(upstream.URL)

	req := httptest.NewRequest(http.MethodGet, "http://proxy.example/resource", nil)
	req.RemoteAddr = "203.0.113.9:12345"
	req.Host = "attacker.example"

	rec := httptest.NewRecorder()
	NewReverseProxy(target).ServeHTTP(rec, req)

	if got == nil {
		t.Fatal("upstream did not receive the request")
	}
	if got.Host != target.Host {
		t.Errorf("upstream Host = %q, want %q", got.Host, target.Host)
	}
}

// 認証済みリクエストでは idproxy が検証した身元が upstream に渡ること。
func TestNewReverseProxy_SetsAuthenticatedIdentityHeaders(t *testing.T) {
	var got *http.Request
	upstream := newEchoUpstream(t, &got)
	target, _ := url.Parse(upstream.URL)

	req := httptest.NewRequest(http.MethodGet, "http://proxy.example/resource", nil)
	req.RemoteAddr = "203.0.113.9:12345"
	req.Header.Set("X-Forwarded-Email", "spoofed@evil.example")
	user := &User{Subject: "sub-123", Email: "alice@example.com", Name: "Alice"}
	req = req.WithContext(NewContextWithUser(req.Context(), user))

	rec := httptest.NewRecorder()
	NewReverseProxy(target).ServeHTTP(rec, req)

	if got == nil {
		t.Fatal("upstream did not receive the request")
	}
	if v := got.Header.Get("X-Forwarded-User"); v != "sub-123" {
		t.Errorf("X-Forwarded-User = %q, want sub-123", v)
	}
	if v := got.Header.Get("X-Forwarded-Email"); v != "alice@example.com" {
		t.Errorf("X-Forwarded-Email = %q, want alice@example.com", v)
	}
	if v := got.Header.Get("X-Forwarded-Preferred-Username"); v != "Alice" {
		t.Errorf("X-Forwarded-Preferred-Username = %q, want Alice", v)
	}
}

// 未認証リクエストでは身元ヘッダーを一切設定しないこと。
func TestNewReverseProxy_NoIdentityHeadersWhenUnauthenticated(t *testing.T) {
	var got *http.Request
	upstream := newEchoUpstream(t, &got)
	target, _ := url.Parse(upstream.URL)

	req := httptest.NewRequest(http.MethodGet, "http://proxy.example/resource", nil)
	req.RemoteAddr = "203.0.113.9:12345"

	rec := httptest.NewRecorder()
	NewReverseProxy(target).ServeHTTP(rec, req)

	if got == nil {
		t.Fatal("upstream did not receive the request")
	}
	for _, name := range []string{"X-Forwarded-User", "X-Forwarded-Email", "X-Forwarded-Preferred-Username"} {
		if v := got.Header.Get(name); v != "" {
			t.Errorf("%s = %q for unauthenticated request, want empty", name, v)
		}
	}
}

// SSE 透過のため FlushInterval が -1 であること。
func TestNewReverseProxy_FlushInterval(t *testing.T) {
	target, _ := url.Parse("http://upstream.example")
	if fi := NewReverseProxy(target).FlushInterval; fi != -1 {
		t.Errorf("FlushInterval = %v, want -1", fi)
	}
}
