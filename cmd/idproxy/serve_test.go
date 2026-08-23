package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serveThrough は authToken 設定のプロキシへ req を通し、
// upstream が受け取ったリクエストと Host を返す。
func serveThrough(t *testing.T, authToken string, req *http.Request) (*http.Request, string) {
	t.Helper()

	var got *http.Request
	var host string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(r.Context())
		host = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p, err := newReverseProxy(upstream.URL, authToken)
	if err != nil {
		t.Fatalf("newReverseProxy() error: %v", err)
	}

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if got == nil {
		t.Fatalf("upstream did not receive the request (status=%d body=%q)", rec.Code, rec.Body.String())
	}
	return got, host
}

func TestNewReverseProxy_UsesRewriteHook(t *testing.T) {
	proxy, err := newReverseProxy("http://localhost:3000", "")
	if err != nil {
		t.Fatalf("newReverseProxy() error: %v", err)
	}
	if proxy.Director != nil { //nolint:staticcheck // Rewrite 移行の回帰確認として deprecated フィールドが未使用であることを検証する
		t.Error("Director must be nil (Rewrite フックへ移行済みであること)")
	}
	if proxy.Rewrite == nil {
		t.Error("Rewrite must be set")
	}
	if proxy.FlushInterval != -1 {
		t.Errorf("FlushInterval = %v, want -1", proxy.FlushInterval)
	}
}

func TestNewReverseProxy_InjectsUpstreamAuthToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/mcp", nil)
	req.Header.Set("Authorization", "Bearer client-token")

	got, _ := serveThrough(t, "upstream-secret", req)

	values := got.Header["Authorization"]
	if len(values) != 1 {
		t.Fatalf("Authorization values = %q, want exactly 1", values)
	}
	if values[0] != "Bearer upstream-secret" {
		t.Errorf("Authorization = %q, want %q", values[0], "Bearer upstream-secret")
	}
	for name, vals := range got.Header {
		for _, v := range vals {
			if strings.Contains(v, "client-token") {
				t.Errorf("client token leaked into header %s: %q", name, v)
			}
		}
	}
}

// golang/go#50580 の回帰: Director フックでは hop-by-hop 除去が注入後に走るため
// Connection: Authorization を送られると注入したヘッダーが落ちる。
func TestNewReverseProxy_InjectionSurvivesConnectionHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/mcp", nil)
	req.Header.Set("Authorization", "Bearer client-token")
	req.Header.Set("Connection", "Authorization")

	got, _ := serveThrough(t, "upstream-secret", req)

	if v := got.Header.Get("Authorization"); v != "Bearer upstream-secret" {
		t.Errorf("Authorization = %q, want %q", v, "Bearer upstream-secret")
	}
}

func TestNewReverseProxy_NoTokenPassesClientAuthorization(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/mcp", nil)
	req.Header.Set("Authorization", "Bearer client-token")

	got, _ := serveThrough(t, "", req)

	if v := got.Header.Get("Authorization"); v != "Bearer client-token" {
		t.Errorf("Authorization = %q, want %q (未設定時は素通し)", v, "Bearer client-token")
	}
}

func TestNewReverseProxy_PassesThroughMCPHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/mcp", nil)
	headers := map[string]string{
		"Mcp-Method":     "tools/call",
		"Mcp-Name":       "focal",
		"x-mcp-header":   "custom-value",
		"Mcp-Session-Id": "session-123",
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	got, _ := serveThrough(t, "upstream-secret", req)

	for k, want := range headers {
		if v := got.Header.Get(k); v != want {
			t.Errorf("%s = %q, want %q", k, v, want)
		}
	}
}

func TestNewReverseProxy_PreservesHostAndForwardedHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/mcp", nil)
	req.RemoteAddr = "203.0.113.9:54321"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "edge.example.com")

	got, host := serveThrough(t, "", req)

	if host != "example.com" {
		t.Errorf("upstream Host = %q, want %q", host, "example.com")
	}
	if v := got.Header.Get("X-Forwarded-For"); v != "203.0.113.9" {
		t.Errorf("X-Forwarded-For = %q, want %q", v, "203.0.113.9")
	}
	if v := got.Header.Get("X-Forwarded-Proto"); v != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want %q (エッジの値を上書きしないこと)", v, "https")
	}
	if v := got.Header.Get("X-Forwarded-Host"); v != "edge.example.com" {
		t.Errorf("X-Forwarded-Host = %q, want %q", v, "edge.example.com")
	}
}

// Director 時代は Connection に列挙されたヘッダーが hop-by-hop 除去で落ちる。
// Rewrite 移行後も復元せず同じ挙動を保つ。
func TestNewReverseProxy_DropsConnectionListedForwardedHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/mcp", nil)
	req.RemoteAddr = "203.0.113.9:54321"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Connection", "X-Forwarded-Proto")

	got, _ := serveThrough(t, "", req)

	if v := got.Header.Get("X-Forwarded-Proto"); v != "" {
		t.Errorf("X-Forwarded-Proto = %q, want empty (hop-by-hop として除去されること)", v)
	}
}

func TestNewReverseProxy_AppendsToExistingXForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/mcp", nil)
	req.RemoteAddr = "203.0.113.9:54321"
	req.Header.Set("X-Forwarded-For", "198.51.100.7")

	got, _ := serveThrough(t, "", req)

	want := "198.51.100.7, 203.0.113.9"
	if v := got.Header.Get("X-Forwarded-For"); v != want {
		t.Errorf("X-Forwarded-For = %q, want %q", v, want)
	}
}
