package idproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/youyo/idproxy/testutil"
)

// setupBrowserAuth はテスト用の BrowserAuth を構築するヘルパー。
// MockIdP を起動し、ProviderManager / SessionManager / Store を初期化して返す。
func setupBrowserAuth(t *testing.T, opts ...func(*Config)) (*BrowserAuth, *testutil.MockIdP) {
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
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("cfg.Validate() failed: %v", err)
	}

	pm, err := NewProviderManager(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewProviderManager() failed: %v", err)
	}

	sm, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("NewSessionManager() failed: %v", err)
	}

	ba := NewBrowserAuth(cfg, pm, sm, st)

	return ba, idp
}

func TestNewBrowserAuth(t *testing.T) {
	ba, _ := setupBrowserAuth(t)
	if ba == nil {
		t.Fatal("NewBrowserAuth() returned nil")
	}
}

func TestLoginHandler_SingleProvider_RedirectsToIdP(t *testing.T) {
	ba, idp := setupBrowserAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()

	ba.LoginHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatal("Location header is empty")
	}

	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("failed to parse Location: %v", err)
	}

	// IdP の authorize エンドポイントにリダイレクトされること
	if !strings.HasPrefix(loc, idp.Issuer()+"/authorize") {
		t.Errorf("expected redirect to IdP authorize endpoint, got %s", loc)
	}

	// 必須パラメータの存在確認
	q := u.Query()
	if q.Get("client_id") != "test-client-id" {
		t.Errorf("client_id = %q, want %q", q.Get("client_id"), "test-client-id")
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q, want %q", q.Get("response_type"), "code")
	}
	if q.Get("state") == "" {
		t.Error("state parameter is missing")
	}
	if q.Get("nonce") == "" {
		t.Error("nonce parameter is missing")
	}
	if q.Get("redirect_uri") == "" {
		t.Error("redirect_uri parameter is missing")
	}
	if q.Get("scope") == "" {
		t.Error("scope parameter is missing")
	}
}

func TestLoginHandler_WithProviderParam(t *testing.T) {
	ba, idp := setupBrowserAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/login?provider="+url.QueryEscape(idp.Issuer()), nil)
	rec := httptest.NewRecorder()

	ba.LoginHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, idp.Issuer()+"/authorize") {
		t.Errorf("expected redirect to IdP, got %s", loc)
	}
}

func TestLoginHandler_InvalidProvider_Returns400(t *testing.T) {
	ba, _ := setupBrowserAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/login?provider=https://unknown.example.com", nil)
	rec := httptest.NewRecorder()

	ba.LoginHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestLoginHandler_PreservesOriginalURL(t *testing.T) {
	ba, _ := setupBrowserAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/login?redirect_to=/dashboard", nil)
	rec := httptest.NewRecorder()

	ba.LoginHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}

	// state が保存されており、redirect_to が関連付けられていることを検証
	// (callback テストで実際にリダイレクト先が /dashboard になることを確認)
}

func TestCallbackHandler_FullFlow(t *testing.T) {
	ba, idp := setupBrowserAuth(t)

	// Step 1: /login でリダイレクトを取得
	loginReq := httptest.NewRequest(http.MethodGet, "/login?redirect_to=/protected", nil)
	loginRec := httptest.NewRecorder()
	ba.LoginHandler().ServeHTTP(loginRec, loginReq)

	if loginRec.Code != http.StatusFound {
		t.Fatalf("login: expected 302, got %d", loginRec.Code)
	}

	loc, err := url.Parse(loginRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse login Location: %v", err)
	}

	state := loc.Query().Get("state")
	nonce := loc.Query().Get("nonce")

	// Step 2: MockIdP で認可コードを発行
	code := idp.IssueCode("test-user-id", "test@example.com", "test-client-id", nonce)

	// Step 3: /callback をシミュレート
	callbackReq := httptest.NewRequest(http.MethodGet,
		"/callback?code="+code+"&state="+state, nil)
	callbackRec := httptest.NewRecorder()
	ba.CallbackHandler().ServeHTTP(callbackRec, callbackReq)

	if callbackRec.Code != http.StatusFound {
		t.Fatalf("callback: expected 302, got %d; body: %s", callbackRec.Code, callbackRec.Body.String())
	}

	// リダイレクト先が元の URL であること
	callbackLoc := callbackRec.Header().Get("Location")
	if callbackLoc != "/protected" {
		t.Errorf("callback redirect = %q, want %q", callbackLoc, "/protected")
	}

	// セッション Cookie が設定されていること
	cookies := callbackRec.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			found = true
			if c.Value == "" {
				t.Error("session cookie value is empty")
			}
		}
	}
	if !found {
		t.Error("session cookie not found in response")
	}
}

// Cognito 対応: name クレーム未設定時に cognito:username を fallback として使う
func TestCallbackHandler_CognitoUsernameFallback(t *testing.T) {
	ba, idp := setupBrowserAuth(t)

	// Cognito 風: name は無く cognito:username が入る
	idp.SetExtraClaims(map[string]any{
		"cognito:username": "alice-cognito",
		"cognito:groups":   []string{"admins"},
	})

	loginReq := httptest.NewRequest(http.MethodGet, "/login?redirect_to=/", nil)
	loginRec := httptest.NewRecorder()
	ba.LoginHandler().ServeHTTP(loginRec, loginReq)
	loc, _ := url.Parse(loginRec.Header().Get("Location"))
	state := loc.Query().Get("state")
	nonce := loc.Query().Get("nonce")

	code := idp.IssueCode("alice-sub", "alice@example.com", "test-client-id", nonce)
	callbackReq := httptest.NewRequest(http.MethodGet, "/callback?code="+code+"&state="+state, nil)
	callbackRec := httptest.NewRecorder()
	ba.CallbackHandler().ServeHTTP(callbackRec, callbackReq)
	if callbackRec.Code != http.StatusFound {
		t.Fatalf("callback: expected 302, got %d; body: %s", callbackRec.Code, callbackRec.Body.String())
	}

	// Cookie からセッションを取得して User.Name を検証
	var sessCookie *http.Cookie
	for _, c := range callbackRec.Result().Cookies() {
		if c.Name == sessionCookieName {
			sessCookie = c
		}
	}
	if sessCookie == nil {
		t.Fatal("session cookie not found")
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(sessCookie)
	sess, err := ba.sm.GetSessionFromRequest(r.Context(), r)
	if err != nil {
		t.Fatalf("GetSessionFromRequest: %v", err)
	}
	if sess == nil || sess.User == nil {
		t.Fatal("session/user is nil")
	}
	if sess.User.Name != "alice-cognito" {
		t.Errorf("User.Name = %q, want alice-cognito (cognito:username fallback)", sess.User.Name)
	}
}

// preferred_username fallback（name も cognito:username も無い場合）
func TestCallbackHandler_PreferredUsernameFallback(t *testing.T) {
	ba, idp := setupBrowserAuth(t)

	idp.SetExtraClaims(map[string]any{
		"preferred_username": "bob-pref",
	})

	loginReq := httptest.NewRequest(http.MethodGet, "/login?redirect_to=/", nil)
	loginRec := httptest.NewRecorder()
	ba.LoginHandler().ServeHTTP(loginRec, loginReq)
	loc, _ := url.Parse(loginRec.Header().Get("Location"))
	state := loc.Query().Get("state")
	nonce := loc.Query().Get("nonce")

	code := idp.IssueCode("bob-sub", "bob@example.com", "test-client-id", nonce)
	callbackReq := httptest.NewRequest(http.MethodGet, "/callback?code="+code+"&state="+state, nil)
	callbackRec := httptest.NewRecorder()
	ba.CallbackHandler().ServeHTTP(callbackRec, callbackReq)
	if callbackRec.Code != http.StatusFound {
		t.Fatalf("callback: expected 302, got %d", callbackRec.Code)
	}

	var sessCookie *http.Cookie
	for _, c := range callbackRec.Result().Cookies() {
		if c.Name == sessionCookieName {
			sessCookie = c
		}
	}
	if sessCookie == nil {
		t.Fatalf("session cookie %q not set on callback response", sessionCookieName)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(sessCookie)
	sess, err := ba.sm.GetSessionFromRequest(r.Context(), r)
	if err != nil {
		t.Fatalf("GetSessionFromRequest: %v", err)
	}
	if sess.User.Name != "bob-pref" {
		t.Errorf("User.Name = %q, want bob-pref (preferred_username fallback)", sess.User.Name)
	}
}

func TestCallbackHandler_DefaultRedirect(t *testing.T) {
	ba, idp := setupBrowserAuth(t)

	// redirect_to を指定せずにログイン
	loginReq := httptest.NewRequest(http.MethodGet, "/login", nil)
	loginRec := httptest.NewRecorder()
	ba.LoginHandler().ServeHTTP(loginRec, loginReq)

	loc, _ := url.Parse(loginRec.Header().Get("Location"))
	state := loc.Query().Get("state")
	nonce := loc.Query().Get("nonce")

	code := idp.IssueCode("test-user-id", "test@example.com", "test-client-id", nonce)

	callbackReq := httptest.NewRequest(http.MethodGet,
		"/callback?code="+code+"&state="+state, nil)
	callbackRec := httptest.NewRecorder()
	ba.CallbackHandler().ServeHTTP(callbackRec, callbackReq)

	if callbackRec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", callbackRec.Code, callbackRec.Body.String())
	}

	// デフォルトは "/" にリダイレクト
	callbackLoc := callbackRec.Header().Get("Location")
	if callbackLoc != "/" {
		t.Errorf("callback redirect = %q, want %q", callbackLoc, "/")
	}
}

func TestCallbackHandler_InvalidState_Returns400(t *testing.T) {
	ba, idp := setupBrowserAuth(t)

	code := idp.IssueCode("test-user-id", "test@example.com", "test-client-id", "some-nonce")

	req := httptest.NewRequest(http.MethodGet,
		"/callback?code="+code+"&state=invalid-state", nil)
	rec := httptest.NewRecorder()
	ba.CallbackHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestCallbackHandler_MissingCode_Returns400(t *testing.T) {
	ba, _ := setupBrowserAuth(t)

	req := httptest.NewRequest(http.MethodGet,
		"/callback?state=some-state", nil)
	rec := httptest.NewRecorder()
	ba.CallbackHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestCallbackHandler_ErrorFromIdP(t *testing.T) {
	ba, _ := setupBrowserAuth(t)

	req := httptest.NewRequest(http.MethodGet,
		"/callback?error=access_denied&error_description=User+denied", nil)
	rec := httptest.NewRecorder()
	ba.CallbackHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestAuthorizeEmail_AllowedDomains(t *testing.T) {
	ba, idp := setupBrowserAuth(t, func(cfg *Config) {
		cfg.AllowedDomains = []string{"example.com"}
	})

	// 許可されたドメインのメール
	loginReq := httptest.NewRequest(http.MethodGet, "/login", nil)
	loginRec := httptest.NewRecorder()
	ba.LoginHandler().ServeHTTP(loginRec, loginReq)

	loc, _ := url.Parse(loginRec.Header().Get("Location"))
	state := loc.Query().Get("state")
	nonce := loc.Query().Get("nonce")

	code := idp.IssueCode("user1", "user@example.com", "test-client-id", nonce)

	callbackReq := httptest.NewRequest(http.MethodGet,
		"/callback?code="+code+"&state="+state, nil)
	callbackRec := httptest.NewRecorder()
	ba.CallbackHandler().ServeHTTP(callbackRec, callbackReq)

	if callbackRec.Code != http.StatusFound {
		t.Fatalf("allowed domain: expected 302, got %d; body: %s", callbackRec.Code, callbackRec.Body.String())
	}
}

func TestAuthorizeEmail_DeniedDomain(t *testing.T) {
	ba, idp := setupBrowserAuth(t, func(cfg *Config) {
		cfg.AllowedDomains = []string{"allowed.com"}
	})

	loginReq := httptest.NewRequest(http.MethodGet, "/login", nil)
	loginRec := httptest.NewRecorder()
	ba.LoginHandler().ServeHTTP(loginRec, loginReq)

	loc, _ := url.Parse(loginRec.Header().Get("Location"))
	state := loc.Query().Get("state")
	nonce := loc.Query().Get("nonce")

	code := idp.IssueCode("user1", "user@denied.com", "test-client-id", nonce)

	callbackReq := httptest.NewRequest(http.MethodGet,
		"/callback?code="+code+"&state="+state, nil)
	callbackRec := httptest.NewRecorder()
	ba.CallbackHandler().ServeHTTP(callbackRec, callbackReq)

	if callbackRec.Code != http.StatusForbidden {
		t.Fatalf("denied domain: expected 403, got %d", callbackRec.Code)
	}
}

func TestAuthorizeEmail_AllowedEmails(t *testing.T) {
	ba, idp := setupBrowserAuth(t, func(cfg *Config) {
		cfg.AllowedDomains = []string{"other.com"}
		cfg.AllowedEmails = []string{"special@denied.com"}
	})

	loginReq := httptest.NewRequest(http.MethodGet, "/login", nil)
	loginRec := httptest.NewRecorder()
	ba.LoginHandler().ServeHTTP(loginRec, loginReq)

	loc, _ := url.Parse(loginRec.Header().Get("Location"))
	state := loc.Query().Get("state")
	nonce := loc.Query().Get("nonce")

	// AllowedEmails に含まれるアドレス（ドメインは denied.com だが個別許可）
	code := idp.IssueCode("user1", "special@denied.com", "test-client-id", nonce)

	callbackReq := httptest.NewRequest(http.MethodGet,
		"/callback?code="+code+"&state="+state, nil)
	callbackRec := httptest.NewRecorder()
	ba.CallbackHandler().ServeHTTP(callbackRec, callbackReq)

	if callbackRec.Code != http.StatusFound {
		t.Fatalf("allowed email: expected 302, got %d; body: %s", callbackRec.Code, callbackRec.Body.String())
	}
}

func TestAuthorizeEmail_NoDomainOrEmailRestrictions(t *testing.T) {
	ba, idp := setupBrowserAuth(t)
	// AllowedDomains も AllowedEmails も未設定 → 全てのメールを許可

	loginReq := httptest.NewRequest(http.MethodGet, "/login", nil)
	loginRec := httptest.NewRecorder()
	ba.LoginHandler().ServeHTTP(loginRec, loginReq)

	loc, _ := url.Parse(loginRec.Header().Get("Location"))
	state := loc.Query().Get("state")
	nonce := loc.Query().Get("nonce")

	code := idp.IssueCode("user1", "anyone@anywhere.com", "test-client-id", nonce)

	callbackReq := httptest.NewRequest(http.MethodGet,
		"/callback?code="+code+"&state="+state, nil)
	callbackRec := httptest.NewRecorder()
	ba.CallbackHandler().ServeHTTP(callbackRec, callbackReq)

	if callbackRec.Code != http.StatusFound {
		t.Fatalf("no restrictions: expected 302, got %d; body: %s", callbackRec.Code, callbackRec.Body.String())
	}
}

func TestSelectionHandler_SingleProvider_RedirectsToLogin(t *testing.T) {
	ba, _ := setupBrowserAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/select", nil)
	rec := httptest.NewRecorder()
	ba.SelectionHandler().ServeHTTP(rec, req)

	// 単一プロバイダーの場合は /login に直接リダイレクト
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "/login") {
		t.Errorf("expected redirect to /login, got %s", loc)
	}
}

func TestSelectionHandler_MultipleProviders_ShowsPage(t *testing.T) {
	idp1 := testutil.NewMockIdP(t)
	idp2 := testutil.NewMockIdP(t)
	st := newTestMemoryStore()

	cfg := Config{
		Providers: []OIDCProvider{
			{
				Issuer:       idp1.Issuer(),
				ClientID:     "client-1",
				ClientSecret: "secret-1",
			},
			{
				Issuer:       idp2.Issuer(),
				ClientID:     "client-2",
				ClientSecret: "secret-2",
			},
		},
		ExternalURL:  "http://localhost:8080",
		CookieSecret: []byte("test-cookie-secret-32-bytes-long!"),
		Store:        st,
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("cfg.Validate() failed: %v", err)
	}

	pm, err := NewProviderManager(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewProviderManager() failed: %v", err)
	}

	sm, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("NewSessionManager() failed: %v", err)
	}

	ba := NewBrowserAuth(cfg, pm, sm, st)

	req := httptest.NewRequest(http.MethodGet, "/select", nil)
	rec := httptest.NewRecorder()
	ba.SelectionHandler().ServeHTTP(rec, req)

	// 複数プロバイダーの場合は選択ページを表示
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Sign in") {
		t.Error("selection page should contain 'Sign in'")
	}
}

func TestIsEmailAuthorized(t *testing.T) {
	tests := []struct {
		name           string
		email          string
		allowedDomains []string
		allowedEmails  []string
		want           bool
	}{
		{
			name:  "no restrictions allows all",
			email: "anyone@anywhere.com",
			want:  true,
		},
		{
			name:           "allowed domain matches",
			email:          "user@example.com",
			allowedDomains: []string{"example.com"},
			want:           true,
		},
		{
			name:           "denied domain rejects",
			email:          "user@other.com",
			allowedDomains: []string{"example.com"},
			want:           false,
		},
		{
			name:          "allowed email matches exactly",
			email:         "special@other.com",
			allowedEmails: []string{"special@other.com"},
			want:          true,
		},
		{
			name:           "allowed email overrides domain deny",
			email:          "special@other.com",
			allowedDomains: []string{"example.com"},
			allowedEmails:  []string{"special@other.com"},
			want:           true,
		},
		{
			name:           "case insensitive domain check",
			email:          "User@Example.COM",
			allowedDomains: []string{"example.com"},
			want:           true,
		},
		{
			name:          "case insensitive email check",
			email:         "User@Example.COM",
			allowedEmails: []string{"user@example.com"},
			want:          true,
		},
		{
			name:           "empty email is denied",
			email:          "",
			allowedDomains: []string{"example.com"},
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isEmailAuthorized(tt.email, tt.allowedDomains, tt.allowedEmails)
			if got != tt.want {
				t.Errorf("isEmailAuthorized(%q, %v, %v) = %v, want %v",
					tt.email, tt.allowedDomains, tt.allowedEmails, got, tt.want)
			}
		})
	}
}

// --- M23: DefaultPostLoginPath / OnAuthenticated / Validator テスト ---

// performLogin は MockIdP を相手に LoginHandler + CallbackHandler を流して
// state/code/redirect を解決し、最終の callback ResponseRecorder を返す。
// 認証は成功する前提。失敗時は t.Fatalf。
func performLogin(t *testing.T, ba *BrowserAuth, idp *testutil.MockIdP, redirectToQuery string) *httptest.ResponseRecorder {
	t.Helper()
	target := "/login"
	if redirectToQuery != "" {
		target += "?redirect_to=" + url.QueryEscape(redirectToQuery)
	}
	loginReq := httptest.NewRequest(http.MethodGet, target, nil)
	loginRec := httptest.NewRecorder()
	ba.LoginHandler().ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusFound {
		t.Fatalf("login: expected 302, got %d (body: %s)", loginRec.Code, loginRec.Body.String())
	}
	loc, _ := url.Parse(loginRec.Header().Get("Location"))
	state := loc.Query().Get("state")
	nonce := loc.Query().Get("nonce")
	code := idp.IssueCode("test-user-id", "test@example.com", "test-client-id", nonce)

	cbReq := httptest.NewRequest(http.MethodGet,
		"/callback?code="+code+"&state="+state, nil)
	cbRec := httptest.NewRecorder()
	ba.CallbackHandler().ServeHTTP(cbRec, cbReq)
	return cbRec
}

// stateRedirectURIFromLogin は LoginHandler を呼んで state に保存された RedirectURI を取得する。
func stateRedirectURIFromLogin(t *testing.T, ba *BrowserAuth, redirectToQuery string) string {
	t.Helper()
	target := "/login"
	if redirectToQuery != "" {
		target += "?redirect_to=" + url.QueryEscape(redirectToQuery)
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	ba.LoginHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("login: expected 302, got %d", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	state := loc.Query().Get("state")
	sd, err := ba.store.GetAuthCode(context.Background(), state)
	if err != nil || sd == nil {
		t.Fatalf("GetAuthCode(state=%q) failed: data=%v err=%v", state, sd, err)
	}
	return sd.RedirectURI
}

// T1: DefaultPostLoginPath="/dashboard" + クエリなしで state.RedirectURI が "/dashboard"。
func TestLoginHandler_DefaultPostLoginPath_Configured(t *testing.T) {
	ba, _ := setupBrowserAuth(t, func(c *Config) {
		c.DefaultPostLoginPath = "/dashboard"
	})
	got := stateRedirectURIFromLogin(t, ba, "")
	if got != "/dashboard" {
		t.Errorf("state.RedirectURI = %q, want %q", got, "/dashboard")
	}
}

// T2: DefaultPostLoginPath="" + クエリなしで state.RedirectURI が "/"（後方互換）。
func TestLoginHandler_DefaultPostLoginPath_Empty(t *testing.T) {
	ba, _ := setupBrowserAuth(t)
	got := stateRedirectURIFromLogin(t, ba, "")
	if got != "/" {
		t.Errorf("state.RedirectURI = %q, want %q", got, "/")
	}
}

// T3: Validator が設定済みの場合、相対パスはそのまま通過する。
func TestLoginHandler_RedirectValidator_AcceptsRelativePath(t *testing.T) {
	ba, _ := setupBrowserAuth(t, func(c *Config) {
		c.UseStrictPostLoginRedirectValidator()
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login?redirect_to=/foo", nil)
	ba.LoginHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 for relative path with Strict Validator, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

// T4: OnAuthenticated が ("/custom", false) を返したら /custom へ 302。
func TestCallbackHandler_OnAuthenticated_OverridesRedirect(t *testing.T) {
	ba, idp := setupBrowserAuth(t, func(c *Config) {
		c.OnAuthenticated = func(w http.ResponseWriter, r *http.Request, user *User) (string, bool) {
			return "/custom", false
		}
	})
	rec := performLogin(t, ba, idp, "/protected")
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/custom" {
		t.Errorf("Location = %q, want %q", loc, "/custom")
	}
}

// T5: OnAuthenticated が ("", true) を返し、内部で 200 OK を書き込む。
func TestCallbackHandler_OnAuthenticated_Handled(t *testing.T) {
	ba, idp := setupBrowserAuth(t, func(c *Config) {
		c.OnAuthenticated = func(w http.ResponseWriter, r *http.Request, user *User) (string, bool) {
			w.WriteHeader(http.StatusOK)
			return "", true
		}
	})
	rec := performLogin(t, ba, idp, "/protected")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("Location should be empty for handled=true, got %q", loc)
	}
}

// T6: OnAuthenticated 未設定なら現状通り stateData.RedirectURI へ 302（既存テストの回帰確認）。
func TestCallbackHandler_OnAuthenticated_Nil_Fallback(t *testing.T) {
	ba, idp := setupBrowserAuth(t)
	rec := performLogin(t, ba, idp, "/protected")
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/protected" {
		t.Errorf("Location = %q, want %q", loc, "/protected")
	}
}

// T7: OnAuthenticated が ("", false) を返した場合は state の RedirectURI を使う。
func TestCallbackHandler_OnAuthenticated_EmptyReturn_Fallback(t *testing.T) {
	ba, idp := setupBrowserAuth(t, func(c *Config) {
		c.OnAuthenticated = func(w http.ResponseWriter, r *http.Request, user *User) (string, bool) {
			return "", false
		}
	})
	rec := performLogin(t, ba, idp, "/protected")
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/protected" {
		t.Errorf("Location = %q, want %q", loc, "/protected")
	}
}

// T20: OnAuthenticated が panic したら 500 を返す。
func TestCallbackHandler_HookPanic_Returns500(t *testing.T) {
	ba, idp := setupBrowserAuth(t, func(c *Config) {
		c.OnAuthenticated = func(w http.ResponseWriter, r *http.Request, user *User) (string, bool) {
			panic("boom")
		}
	})
	rec := performLogin(t, ba, idp, "/protected")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 after hook panic, got %d", rec.Code)
	}
}

// T21: フックが http.Redirect で書きつつ handled=false を返した場合、
// 最初の Location ヘッダがフック側の指定値であり、BrowserAuth は二重書き込みを行わない。
func TestCallbackHandler_HookAlreadyWrote_NoSecondRedirect(t *testing.T) {
	ba, idp := setupBrowserAuth(t, func(c *Config) {
		c.OnAuthenticated = func(w http.ResponseWriter, r *http.Request, user *User) (string, bool) {
			http.Redirect(w, r, "/x", http.StatusFound)
			return "", false
		}
	})
	rec := performLogin(t, ba, idp, "/protected")
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/x" {
		t.Errorf("Location = %q, want %q", loc, "/x")
	}
}

// T22: 呼び出し中に r.Context() が canceled になっても 200/300 系の書き込みをせず終了する。
// （ハンドラ自身が return しているかは外部観測できないため、status code が default 200 で
//
//	Location ヘッダ無しという外部可観測契約のみ検証する。）
func TestCallbackHandler_HookContextCanceled(t *testing.T) {
	cancelCh := make(chan struct{})
	ba, idp := setupBrowserAuth(t, func(c *Config) {
		c.OnAuthenticated = func(w http.ResponseWriter, r *http.Request, user *User) (string, bool) {
			// 呼び出し中に context を cancel する
			if cancel, ok := r.Context().Value(testCancelKey{}).(context.CancelFunc); ok {
				cancel()
				close(cancelCh)
			}
			return "/should-not-be-used", false
		}
	})

	// /login で state 確立
	loginReq := httptest.NewRequest(http.MethodGet, "/login?redirect_to=/protected", nil)
	loginRec := httptest.NewRecorder()
	ba.LoginHandler().ServeHTTP(loginRec, loginReq)
	loc, _ := url.Parse(loginRec.Header().Get("Location"))
	state := loc.Query().Get("state")
	nonce := loc.Query().Get("nonce")
	code := idp.IssueCode("u", "u@example.com", "test-client-id", nonce)

	// /callback リクエストに cancel 可能 context を仕込む
	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, testCancelKey{}, cancel)
	cbReq := httptest.NewRequest(http.MethodGet, "/callback?code="+code+"&state="+state, nil).WithContext(ctx)
	cbRec := httptest.NewRecorder()
	ba.CallbackHandler().ServeHTTP(cbRec, cbReq)

	// hook 内で cancel された場合、BrowserAuth は何も書かないため
	// Location ヘッダは空 / 302 になっていないことを検証
	if cbRec.Header().Get("Location") != "" {
		t.Errorf("Location should be empty after context cancellation, got %q", cbRec.Header().Get("Location"))
	}
	if cbRec.Code == http.StatusFound {
		t.Errorf("status should not be 302 after context cancellation, got %d", cbRec.Code)
	}
}

// testCancelKey は T22 用の context key
type testCancelKey struct{}

// T23: Validator が panic したら 500 を返す。
// Validator は CallbackHandler 内のフック戻り値検査時に panic させ、500 を期待する。
// （LoginHandler 内では reject 系の正常パスで panic させずに通す。）
func TestCallbackHandler_ValidatorPanic_Returns500(t *testing.T) {
	ba, idp := setupBrowserAuth(t, func(c *Config) {
		c.PostLoginRedirectValidator = func(s string) error {
			// "/panic-me" だけ panic させる。LoginHandler の "/" や "/protected" は通す。
			if s == "/panic-me" {
				panic("validator boom")
			}
			return nil
		}
		c.OnAuthenticated = func(w http.ResponseWriter, r *http.Request, user *User) (string, bool) {
			return "/panic-me", false
		}
	})
	rec := performLogin(t, ba, idp, "/protected")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 after validator panic in callback hook, got %d", rec.Code)
	}
}

// T24: handled=true && redirectTo!="" のとき、フック側応答を尊重しリダイレクトしない。
func TestCallbackHandler_HandledTrue_RedirectToNonEmpty_RedirectIgnored(t *testing.T) {
	ba, idp := setupBrowserAuth(t, func(c *Config) {
		c.OnAuthenticated = func(w http.ResponseWriter, r *http.Request, user *User) (string, bool) {
			// フックは何も書かないが handled=true を宣言。redirectTo は ignore される。
			return "/x-ignored", true
		}
	})
	rec := performLogin(t, ba, idp, "/protected")
	if rec.Code == http.StatusFound {
		t.Errorf("status should not be 302 when handled=true; got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("Location should be empty when handled=true, got %q", loc)
	}
}

// T25: SelectionHandler に redirect_to が指定された場合、loginURL の値が URL escape されている。
func TestSelectionHandler_RedirectToIsURLEscaped(t *testing.T) {
	// 複数プロバイダーだと選択ページが返るため、単一プロバイダー（既存 setupBrowserAuth）でテスト。
	ba, _ := setupBrowserAuth(t)
	req := httptest.NewRequest(http.MethodGet, "/select?redirect_to=/foo%26bar=baz", nil)
	rec := httptest.NewRecorder()
	ba.SelectionHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	// URL escape された後の `%2F` (`/`) と `%26` (`&`) を含むこと
	if !strings.Contains(loc, "redirect_to=") {
		t.Fatalf("Location should contain redirect_to=, got %q", loc)
	}
	// `&` が escape されていないと SelectionHandler の素朴連結バグが残存
	// 連結後の loginURL を分解し、redirect_to クエリ値が "/foo&bar=baz" にデコードされること
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	gotRT := u.Query().Get("redirect_to")
	if gotRT != "/foo&bar=baz" {
		t.Errorf("redirect_to (decoded) = %q, want %q", gotRT, "/foo&bar=baz")
	}
}

// T26: Strict Validator 設定済みでフックが unsafe redirect ("javascript:...") を返したら 500。
func TestCallbackHandler_HookReturnsInvalidRedirect_RejectedByValidator(t *testing.T) {
	ba, idp := setupBrowserAuth(t, func(c *Config) {
		c.UseStrictPostLoginRedirectValidator()
		c.OnAuthenticated = func(w http.ResponseWriter, r *http.Request, user *User) (string, bool) {
			return "javascript:alert(1)", false
		}
	})
	rec := performLogin(t, ba, idp, "")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for unsafe hook redirect, got %d", rec.Code)
	}
}

// T27: Validator=nil でフックが ("/x", false) を返した場合は /x へ 302（既存動作互換）。
func TestCallbackHandler_HookReturnsValidRedirect_ValidatorNil_Passes(t *testing.T) {
	ba, idp := setupBrowserAuth(t, func(c *Config) {
		c.PostLoginRedirectValidator = nil
		c.OnAuthenticated = func(w http.ResponseWriter, r *http.Request, user *User) (string, bool) {
			return "/x", false
		}
	})
	rec := performLogin(t, ba, idp, "")
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/x" {
		t.Errorf("Location = %q, want %q", loc, "/x")
	}
}

// 追加: LoginHandler の redirect_to クエリが Strict Validator で reject される場合 400。
func TestLoginHandler_RedirectValidator_Reject_400(t *testing.T) {
	ba, _ := setupBrowserAuth(t, func(c *Config) {
		c.UseStrictPostLoginRedirectValidator()
	})
	req := httptest.NewRequest(http.MethodGet, "/login?redirect_to="+url.QueryEscape("javascript:alert(1)"), nil)
	rec := httptest.NewRecorder()
	ba.LoginHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for javascript: redirect_to, got %d", rec.Code)
	}
}

// 追加: SelectionHandler の redirect_to クエリが Strict Validator で reject される場合 400。
func TestSelectionHandler_RedirectValidator_Reject_400(t *testing.T) {
	ba, _ := setupBrowserAuth(t, func(c *Config) {
		c.UseStrictPostLoginRedirectValidator()
	})
	req := httptest.NewRequest(http.MethodGet, "/select?redirect_to="+url.QueryEscape("//evil.example.com/x"), nil)
	rec := httptest.NewRecorder()
	ba.SelectionHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for protocol-relative redirect_to in /select, got %d", rec.Code)
	}
}
