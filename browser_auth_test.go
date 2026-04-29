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
