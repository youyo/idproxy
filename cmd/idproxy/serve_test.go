package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	idproxy "github.com/youyo/idproxy"
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

// authenticatedRequest は Auth.Wrap 相当の認証済みコンテキストを持つリクエストを返す。
func authenticatedRequest(req *http.Request, user *idproxy.User) *http.Request {
	return req.WithContext(idproxy.NewContextWithUser(req.Context(), user))
}

func TestNewReverseProxy_StripsClientIdentityHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/mcp", nil)
	spoofed := []string{
		"X-Forwarded-User",
		"X-Forwarded-Email",
		"X-Forwarded-Preferred-Username",
		"X-Forwarded-Groups",
		"X-Auth-Request-User",
		"X-Auth-Request-Email",
		"X-Auth-Request-Groups",
		"X-Auth-Request-Preferred-Username",
		"X-Remote-User",
		"X-Remote-Email",
		"X-Remote-Groups",
		"X-Authenticated-User",
		"X-User",
		"X-Email",
	}
	for _, name := range spoofed {
		req.Header.Set(name, "admin@corp.example")
	}
	// 非正規形の名前で送られても（net/http サーバーは受信時に正規化する）落ちること。
	req.Header.Set("x-auth-request-email", "admin@corp.example")

	got, _ := serveThrough(t, "upstream-secret", req)

	for name, vals := range got.Header {
		for _, v := range vals {
			if strings.Contains(v, "admin@corp.example") {
				t.Errorf("spoofed identity leaked into header %s: %q", name, v)
			}
		}
	}
}

func TestNewReverseProxy_SetsIdentityHeadersFromAuthenticatedUser(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/mcp", nil)
	req.Header.Set("X-Forwarded-Email", "admin@corp.example")
	req = authenticatedRequest(req, &idproxy.User{
		Subject: "sub-123",
		Email:   "user@corp.example",
	})

	got, _ := serveThrough(t, "upstream-secret", req)

	if v := got.Header.Get("X-Forwarded-User"); v != "sub-123" {
		t.Errorf("X-Forwarded-User = %q, want %q", v, "sub-123")
	}
	if v := got.Header["X-Forwarded-Email"]; len(v) != 1 || v[0] != "user@corp.example" {
		t.Errorf("X-Forwarded-Email = %q, want exactly [%q]", v, "user@corp.example")
	}
}

func TestNewReverseProxy_NoIdentityHeadersWhenUnauthenticated(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/mcp", nil)

	got, _ := serveThrough(t, "", req)

	for _, name := range []string{"X-Forwarded-User", "X-Forwarded-Email"} {
		if v := got.Header.Get(name); v != "" {
			t.Errorf("%s = %q, want empty (未認証時は何もセットしないこと)", name, v)
		}
	}
}

// Subject/Email が空の User では該当ヘッダーを付けない（空値の押し付けを避ける）。
func TestNewReverseProxy_SkipsEmptyIdentityFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/mcp", nil)
	req = authenticatedRequest(req, &idproxy.User{Subject: "sub-123"})

	got, _ := serveThrough(t, "", req)

	if v := got.Header.Get("X-Forwarded-User"); v != "sub-123" {
		t.Errorf("X-Forwarded-User = %q, want %q", v, "sub-123")
	}
	if _, ok := got.Header["X-Forwarded-Email"]; ok {
		t.Error("X-Forwarded-Email should be absent when User.Email is empty")
	}
}

func TestNewReverseProxy_StripsSessionCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/mcp", nil)
	req.AddCookie(&http.Cookie{Name: "upstream_pref", Value: "dark"})
	req.AddCookie(&http.Cookie{Name: idproxy.SessionCookieName, Value: "encrypted-session"})
	req.AddCookie(&http.Cookie{Name: "other", Value: "keep-me"})

	got, _ := serveThrough(t, "upstream-secret", req)

	if _, err := got.Cookie(idproxy.SessionCookieName); err != http.ErrNoCookie {
		t.Errorf("session cookie %q must not reach upstream (err=%v)", idproxy.SessionCookieName, err)
	}
	if strings.Contains(got.Header.Get("Cookie"), "encrypted-session") {
		t.Errorf("session cookie value leaked: %q", got.Header.Get("Cookie"))
	}
	for name, want := range map[string]string{"upstream_pref": "dark", "other": "keep-me"} {
		c, err := got.Cookie(name)
		if err != nil {
			t.Errorf("cookie %q was dropped: %v", name, err)
			continue
		}
		if c.Value != want {
			t.Errorf("cookie %q = %q, want %q", name, c.Value, want)
		}
	}
}

func TestNewReverseProxy_DeletesCookieHeaderWhenOnlySessionCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/mcp", nil)
	req.AddCookie(&http.Cookie{Name: idproxy.SessionCookieName, Value: "encrypted-session"})

	got, _ := serveThrough(t, "upstream-secret", req)

	if _, ok := got.Header["Cookie"]; ok {
		t.Errorf("Cookie header = %q, want absent", got.Header.Get("Cookie"))
	}
}

// UPSTREAM_AUTH_TOKEN 未設定時は既定挙動（素通し）を変えない。
func TestNewReverseProxy_NoTokenKeepsSessionCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/mcp", nil)
	req.AddCookie(&http.Cookie{Name: idproxy.SessionCookieName, Value: "encrypted-session"})

	got, _ := serveThrough(t, "", req)

	c, err := got.Cookie(idproxy.SessionCookieName)
	if err != nil {
		t.Fatalf("session cookie should pass through when no token is set: %v", err)
	}
	if c.Value != "encrypted-session" {
		t.Errorf("session cookie = %q, want %q", c.Value, "encrypted-session")
	}
}

// セッション Cookie が無いリクエストでは Cookie ヘッダーに触れない。
func TestNewReverseProxy_LeavesOtherCookiesUntouched(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/mcp", nil)
	req.Header.Set("Cookie", "a=1; b=2")

	got, _ := serveThrough(t, "upstream-secret", req)

	if v := got.Header.Get("Cookie"); v != "a=1; b=2" {
		t.Errorf("Cookie = %q, want %q", v, "a=1; b=2")
	}
}
