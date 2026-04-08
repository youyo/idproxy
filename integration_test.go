//go:build integration

package idproxy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	idproxy "github.com/youyo/idproxy"
	"github.com/youyo/idproxy/store"
	"github.com/youyo/idproxy/testutil"
)

// --- ヘルパー ---

// cookieSecret はテスト用の 32 バイト Cookie シークレット。
var cookieSecret = []byte("integration-test-cookie-secret!!")

// newNoRedirectClient はリダイレクトを追わない HTTP クライアントを返す。
func newNoRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// newFollowRedirectClient はリダイレクト先に Cookie を引き継ぐ HTTP クライアントを返す。
// ただし同一オリジンのリダイレクトのみ Cookie を引き継ぐ。
func newFollowRedirectClient(jar http.CookieJar) *http.Client {
	return &http.Client{
		Jar: jar,
	}
}

// setupUpstream はテスト用 upstream サーバーを起動する。
// リクエストの X-Forwarded-User ヘッダー（存在すれば）と upstream からのレスポンスを返す。
func setupUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// コンテキストから User を取得するのではなく、upstream は直接リクエストを受け取る。
		// idproxy の Wrap() は User をコンテキストに注入するが、upstream に渡されるのは
		// リクエストそのもの。ここでは単にリクエストを受け取って 200 を返す。
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
			"path":   r.URL.Path,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// setupSSEUpstream は SSE イベントを送信するテスト用 upstream サーバーを起動する。
func setupSSEUpstream(t *testing.T, events []string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		for _, event := range events {
			fmt.Fprintf(w, "data: %s\n\n", event)
			flusher.Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// setupAuth は MockIdP と idproxy Auth + httptest.Server を起動する。
// upstream の URL を受け取って、Auth.Wrap(reverseProxy) のサーバーを返す。
// 注意: Auth.Wrap() は upstream にリバースプロキシするのではなく、next ハンドラーに委譲する。
// 統合テストでは upstream へのリバースプロキシの代わりに、直接 next ハンドラーを使用する。
func setupAuth(t *testing.T, mockIdP *testutil.MockIdP, opts ...func(*idproxy.Config)) (*httptest.Server, *idproxy.Config) {
	t.Helper()

	memStore := store.NewMemoryStore()
	t.Cleanup(func() { _ = memStore.Close() })

	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}

	cfg := idproxy.Config{
		Providers: []idproxy.OIDCProvider{
			{
				Issuer:       mockIdP.Issuer(),
				ClientID:     "test-client",
				ClientSecret: "test-secret",
			},
		},
		ExternalURL:  "http://localhost:0", // 後で上書き
		CookieSecret: cookieSecret,
		Store:        memStore,
		OAuth: &idproxy.OAuthConfig{
			SigningKey:          signingKey,
			AllowedRedirectURIs: []string{}, // 後で追加
		},
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	// dummy server を先に起動して ExternalURL を取得
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(dummyHandler)

	cfg.ExternalURL = srv.URL

	// AllowedRedirectURIs にテストサーバー URL を追加
	if cfg.OAuth != nil && len(cfg.OAuth.AllowedRedirectURIs) == 0 {
		cfg.OAuth.AllowedRedirectURIs = []string{
			srv.URL + "/callback",
			"http://localhost:9999/callback",
		}
	}

	ctx := context.Background()
	auth, err := idproxy.New(ctx, cfg)
	if err != nil {
		srv.Close()
		t.Fatalf("failed to create auth: %v", err)
	}

	// upstream ハンドラー: テスト用に User 情報を JSON で返す
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := idproxy.UserFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		if user != nil {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status":  "authenticated",
				"email":   user.Email,
				"subject": user.Subject,
			})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "no-user",
			})
		}
	})

	// サーバーのハンドラーを auth.Wrap(upstream) に差し替え
	srv.Config.Handler = auth.Wrap(upstream)

	return srv, &cfg
}

// setupAuthWithSSEUpstream は SSE upstream 向けの Auth サーバーを起動する。
func setupAuthWithSSEUpstream(t *testing.T, mockIdP *testutil.MockIdP, sseUpstream *httptest.Server) (*httptest.Server, *idproxy.Config) {
	t.Helper()

	memStore := store.NewMemoryStore()
	t.Cleanup(func() { _ = memStore.Close() })

	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}

	cfg := idproxy.Config{
		Providers: []idproxy.OIDCProvider{
			{
				Issuer:       mockIdP.Issuer(),
				ClientID:     "test-client",
				ClientSecret: "test-secret",
			},
		},
		ExternalURL:  "http://localhost:0",
		CookieSecret: cookieSecret,
		Store:        memStore,
		OAuth: &idproxy.OAuthConfig{
			SigningKey:          signingKey,
			AllowedRedirectURIs: []string{},
		},
	}

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(dummyHandler)

	cfg.ExternalURL = srv.URL
	cfg.OAuth.AllowedRedirectURIs = []string{
		srv.URL + "/callback",
		"http://localhost:9999/callback",
	}

	ctx := context.Background()
	auth, err := idproxy.New(ctx, cfg)
	if err != nil {
		srv.Close()
		t.Fatalf("failed to create auth: %v", err)
	}

	// SSE upstream へのリバースプロキシ
	sseTarget, _ := url.Parse(sseUpstream.URL)
	sseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 簡易リバースプロキシ
		proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, sseTarget.String()+r.URL.Path, r.Body)
		if err != nil {
			http.Error(w, "proxy error", http.StatusBadGateway)
			return
		}
		proxyReq.Header = r.Header.Clone()

		resp, err := http.DefaultClient.Do(proxyReq)
		if err != nil {
			http.Error(w, "proxy error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		// ストリーミング: Flush しながらコピー
		flusher, ok := w.(http.Flusher)
		buf := make([]byte, 1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				if ok {
					flusher.Flush()
				}
			}
			if err != nil {
				break
			}
		}
	})

	srv.Config.Handler = auth.Wrap(sseHandler)
	return srv, &cfg
}

// performBrowserLogin は MockIdP を使ってブラウザ認証フローを実行し、セッション Cookie を返す。
func performBrowserLogin(t *testing.T, authSrv *httptest.Server, mockIdP *testutil.MockIdP) []*http.Cookie {
	t.Helper()
	client := newNoRedirectClient()

	// 1. GET /login → IdP にリダイレクト
	loginURL := authSrv.URL + "/login"
	resp, err := client.Get(loginURL)
	if err != nil {
		t.Fatalf("failed to GET /login: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from /login, got %d", resp.StatusCode)
	}

	idpRedirectURL := resp.Header.Get("Location")
	if idpRedirectURL == "" {
		t.Fatal("no Location header from /login")
	}

	// 2. GET IdP /authorize → IdP が callback にリダイレクト
	resp, err = client.Get(idpRedirectURL)
	if err != nil {
		t.Fatalf("failed to GET IdP authorize: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from IdP authorize, got %d", resp.StatusCode)
	}

	callbackURL := resp.Header.Get("Location")
	if callbackURL == "" {
		t.Fatal("no Location header from IdP authorize")
	}

	// 3. GET /callback → セッション Cookie 発行 + リダイレクト
	resp, err = client.Get(callbackURL)
	if err != nil {
		t.Fatalf("failed to GET /callback: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from /callback, got %d", resp.StatusCode)
	}

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookies from /callback")
	}

	return cookies
}

// --- E2E 1: ブラウザ認証フロー ---

func TestIntegration_BrowserAuthFlow(t *testing.T) {
	mockIdP := testutil.NewMockIdP(t)
	authSrv, _ := setupAuth(t, mockIdP)
	defer authSrv.Close()

	client := newNoRedirectClient()

	// Step 1: 未認証のブラウザリクエスト → /login にリダイレクト
	req, _ := http.NewRequest("GET", authSrv.URL+"/some/page", nil)
	req.Header.Set("Accept", "text/html")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed initial request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 redirect for unauthenticated browser request, got %d", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	if !strings.Contains(location, "/login") {
		t.Fatalf("expected redirect to /login, got %s", location)
	}
	if !strings.Contains(location, "redirect_to=") {
		t.Fatalf("expected redirect_to parameter, got %s", location)
	}

	// Step 2: GET /login → IdP にリダイレクト
	resp, err = client.Get(authSrv.URL + "/login")
	if err != nil {
		t.Fatalf("failed GET /login: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from /login, got %d", resp.StatusCode)
	}
	idpRedirectURL := resp.Header.Get("Location")
	if !strings.Contains(idpRedirectURL, mockIdP.Issuer()) {
		t.Fatalf("expected redirect to IdP, got %s", idpRedirectURL)
	}
	// state パラメータがあることを確認
	parsedIdPURL, _ := url.Parse(idpRedirectURL)
	if parsedIdPURL.Query().Get("state") == "" {
		t.Fatal("expected state parameter in IdP redirect URL")
	}
	if parsedIdPURL.Query().Get("nonce") == "" {
		t.Fatal("expected nonce parameter in IdP redirect URL")
	}

	// Step 3: GET IdP /authorize → callback にリダイレクト（MockIdP が自動的にコード生成）
	resp, err = client.Get(idpRedirectURL)
	if err != nil {
		t.Fatalf("failed GET IdP authorize: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from IdP authorize, got %d", resp.StatusCode)
	}
	callbackURL := resp.Header.Get("Location")
	if !strings.Contains(callbackURL, "/callback") {
		t.Fatalf("expected redirect to /callback, got %s", callbackURL)
	}

	// callback URL に code と state があることを確認
	parsedCallbackURL, _ := url.Parse(callbackURL)
	if parsedCallbackURL.Query().Get("code") == "" {
		t.Fatal("expected code parameter in callback URL")
	}
	if parsedCallbackURL.Query().Get("state") == "" {
		t.Fatal("expected state parameter in callback URL")
	}

	// Step 4: GET /callback → セッション Cookie が発行される
	resp, err = client.Get(callbackURL)
	if err != nil {
		t.Fatalf("failed GET /callback: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from /callback, got %d", resp.StatusCode)
	}

	cookies := resp.Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "_idproxy_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected _idproxy_session cookie to be set")
	}

	// Step 5: Cookie 付きリクエスト → upstream に到達
	req, _ = http.NewRequest("GET", authSrv.URL+"/api/data", nil)
	req.AddCookie(sessionCookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("failed authenticated request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for authenticated request, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Step 6: User コンテキストにメール情報があることを確認
	if body["status"] != "authenticated" {
		t.Fatalf("expected status=authenticated, got %s", body["status"])
	}
	if body["email"] != "test@example.com" {
		t.Fatalf("expected email=test@example.com, got %s", body["email"])
	}
}

// --- E2E 2: OAuth 2.1 フルフロー ---

func TestIntegration_OAuth21FullFlow(t *testing.T) {
	mockIdP := testutil.NewMockIdP(t)
	authSrv, cfg := setupAuth(t, mockIdP)
	defer authSrv.Close()

	client := newNoRedirectClient()

	// Step 1: GET /.well-known/oauth-authorization-server → メタデータ取得
	resp, err := client.Get(authSrv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("failed GET metadata: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for metadata, got %d", resp.StatusCode)
	}

	var metadata map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		t.Fatalf("failed to decode metadata: %v", err)
	}

	if metadata["issuer"] != cfg.ExternalURL {
		t.Fatalf("expected issuer=%s, got %v", cfg.ExternalURL, metadata["issuer"])
	}
	if metadata["authorization_endpoint"] == nil {
		t.Fatal("expected authorization_endpoint in metadata")
	}
	if metadata["token_endpoint"] == nil {
		t.Fatal("expected token_endpoint in metadata")
	}
	if metadata["registration_endpoint"] == nil {
		t.Fatal("expected registration_endpoint in metadata")
	}

	// Step 2: DCR: POST /register でクライアント登録
	dcrBody := `{"redirect_uris": ["http://localhost:9999/callback"], "client_name": "integration-test"}`
	resp, err = client.Post(authSrv.URL+"/register", "application/json", strings.NewReader(dcrBody))
	if err != nil {
		t.Fatalf("failed POST /register: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201 for /register, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var dcrResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&dcrResp); err != nil {
		t.Fatalf("failed to decode DCR response: %v", err)
	}

	clientID, ok := dcrResp["client_id"].(string)
	if !ok || clientID == "" {
		t.Fatal("expected client_id in DCR response")
	}

	// Step 3: ブラウザ認証でセッション取得
	cookies := performBrowserLogin(t, authSrv, mockIdP)

	// Step 4: GET /authorize → 認可コード取得
	codeVerifier := "test-code-verifier-that-is-long-enough-for-pkce-validation"
	codeChallenge := idproxy.S256Challenge(codeVerifier)

	authorizeURL := fmt.Sprintf(
		"%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&state=test-state&scope=openid+email",
		authSrv.URL,
		clientID,
		url.QueryEscape("http://localhost:9999/callback"),
		codeChallenge,
	)

	req, _ := http.NewRequest("GET", authorizeURL, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("failed GET /authorize: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from /authorize, got %d", resp.StatusCode)
	}

	redirectLocation := resp.Header.Get("Location")
	parsedRedirect, err := url.Parse(redirectLocation)
	if err != nil {
		t.Fatalf("failed to parse redirect location: %v", err)
	}

	authCode := parsedRedirect.Query().Get("code")
	if authCode == "" {
		t.Fatal("expected code in redirect from /authorize")
	}
	returnedState := parsedRedirect.Query().Get("state")
	if returnedState != "test-state" {
		t.Fatalf("expected state=test-state, got %s", returnedState)
	}

	// Step 5: POST /token → Bearer JWT 取得
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
	}

	resp, err = client.PostForm(authSrv.URL+"/token", tokenForm)
	if err != nil {
		t.Fatalf("failed POST /token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 for /token, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var tokenResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}

	accessToken, ok := tokenResp["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatal("expected access_token in token response")
	}
	if tokenResp["token_type"] != "Bearer" {
		t.Fatalf("expected token_type=Bearer, got %v", tokenResp["token_type"])
	}

	// Step 6: Bearer JWT でリクエスト → upstream に到達確認
	req, _ = http.NewRequest("GET", authSrv.URL+"/api/protected", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("failed Bearer request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 for Bearer request, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var bearerBody map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&bearerBody); err != nil {
		t.Fatalf("failed to decode bearer response: %v", err)
	}
	if bearerBody["status"] != "authenticated" {
		t.Fatalf("expected status=authenticated, got %s", bearerBody["status"])
	}
	if bearerBody["email"] != "test@example.com" {
		t.Fatalf("expected email=test@example.com, got %s", bearerBody["email"])
	}
}

// --- E2E 3: SSE パススルー ---

func TestIntegration_SSEPassthrough(t *testing.T) {
	mockIdP := testutil.NewMockIdP(t)

	// SSE upstream サーバー
	sseEvents := []string{"event1", "event2", "event3"}
	sseUpstream := setupSSEUpstream(t, sseEvents)

	authSrv, _ := setupAuthWithSSEUpstream(t, mockIdP, sseUpstream)
	defer authSrv.Close()

	// ブラウザ認証でセッション Cookie 取得
	cookies := performBrowserLogin(t, authSrv, mockIdP)

	// SSE エンドポイントに Cookie 認証でアクセス
	req, _ := http.NewRequest("GET", authSrv.URL+"/sse", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	// タイムアウト付きクライアント
	sseClient := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := sseClient.Do(req)
	if err != nil {
		t.Fatalf("failed SSE request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 for SSE request, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Content-Type が text/event-stream であることを確認
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("expected Content-Type=text/event-stream, got %s", ct)
	}

	// SSE イベントを読み取り
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read SSE body: %v", err)
	}
	bodyStr := string(body)

	for _, event := range sseEvents {
		expected := "data: " + event
		if !strings.Contains(bodyStr, expected) {
			t.Errorf("expected SSE body to contain %q, got: %s", expected, bodyStr)
		}
	}
}

// --- E2E 4: 複数 IdP 同時テスト ---

func TestIntegration_MultipleIdPs(t *testing.T) {
	mockIdP1 := testutil.NewMockIdP(t)
	mockIdP2 := testutil.NewMockIdP(t)

	memStore := store.NewMemoryStore()
	t.Cleanup(func() { _ = memStore.Close() })

	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}

	cfg := idproxy.Config{
		Providers: []idproxy.OIDCProvider{
			{
				Issuer:       mockIdP1.Issuer(),
				ClientID:     "client-1",
				ClientSecret: "secret-1",
				Name:         "Provider One",
			},
			{
				Issuer:       mockIdP2.Issuer(),
				ClientID:     "client-2",
				ClientSecret: "secret-2",
				Name:         "Provider Two",
			},
		},
		ExternalURL:  "http://localhost:0",
		CookieSecret: cookieSecret,
		Store:        memStore,
		OAuth: &idproxy.OAuthConfig{
			SigningKey: signingKey,
		},
	}

	dummySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	cfg.ExternalURL = dummySrv.URL
	cfg.OAuth.AllowedRedirectURIs = []string{dummySrv.URL + "/callback"}

	ctx := context.Background()
	auth, err := idproxy.New(ctx, cfg)
	if err != nil {
		dummySrv.Close()
		t.Fatalf("failed to create auth: %v", err)
	}

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := idproxy.UserFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		if user != nil {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status":  "authenticated",
				"email":   user.Email,
				"subject": user.Subject,
			})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "no-user",
			})
		}
	})

	dummySrv.Config.Handler = auth.Wrap(upstream)
	defer dummySrv.Close()

	client := newNoRedirectClient()

	// Step 1: 未認証ブラウザリクエスト → /login にリダイレクト
	req, _ := http.NewRequest("GET", dummySrv.URL+"/", nil)
	req.Header.Set("Accept", "text/html")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed initial request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}

	// Step 2: GET /login → 複数プロバイダーなので provider パラメータが必要
	// provider なしで /login → 400 Bad Request
	resp, err = client.Get(dummySrv.URL + "/login")
	if err != nil {
		t.Fatalf("failed GET /login: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for /login without provider, got %d", resp.StatusCode)
	}

	// Step 3: /select ページでプロバイダー選択ページが表示される
	req, _ = http.NewRequest("GET", dummySrv.URL+"/select", nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("failed GET /select: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for /select, got %d", resp.StatusCode)
	}

	selectBody, _ := io.ReadAll(resp.Body)
	selectHTML := string(selectBody)

	// プロバイダー名が表示されること
	if !strings.Contains(selectHTML, "Provider One") {
		t.Fatal("expected 'Provider One' in selection page")
	}
	if !strings.Contains(selectHTML, "Provider Two") {
		t.Fatal("expected 'Provider Two' in selection page")
	}

	// Step 4: Provider One で認証
	resp, err = client.Get(dummySrv.URL + "/login?provider=" + url.QueryEscape(mockIdP1.Issuer()))
	if err != nil {
		t.Fatalf("failed GET /login with provider: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from /login with provider, got %d", resp.StatusCode)
	}

	idpRedirectURL := resp.Header.Get("Location")
	if !strings.Contains(idpRedirectURL, mockIdP1.Issuer()) {
		t.Fatalf("expected redirect to IdP 1, got %s", idpRedirectURL)
	}

	// IdP1 authorize → callback
	resp, err = client.Get(idpRedirectURL)
	if err != nil {
		t.Fatalf("failed GET IdP1 authorize: %v", err)
	}
	resp.Body.Close()

	callbackURL := resp.Header.Get("Location")
	resp, err = client.Get(callbackURL)
	if err != nil {
		t.Fatalf("failed GET /callback: %v", err)
	}
	resp.Body.Close()

	cookies1 := resp.Cookies()
	if len(cookies1) == 0 {
		t.Fatal("no cookies from /callback for IdP 1")
	}

	// Cookie で認証確認
	req, _ = http.NewRequest("GET", dummySrv.URL+"/api/data", nil)
	for _, c := range cookies1 {
		req.AddCookie(c)
	}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("failed authenticated request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body1 map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body1); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if body1["status"] != "authenticated" {
		t.Fatalf("expected authenticated, got %s", body1["status"])
	}

	// Step 5: Provider Two で別セッション認証
	resp, err = client.Get(dummySrv.URL + "/login?provider=" + url.QueryEscape(mockIdP2.Issuer()))
	if err != nil {
		t.Fatalf("failed GET /login with provider 2: %v", err)
	}
	resp.Body.Close()

	idpRedirectURL2 := resp.Header.Get("Location")
	resp, err = client.Get(idpRedirectURL2)
	if err != nil {
		t.Fatalf("failed GET IdP2 authorize: %v", err)
	}
	resp.Body.Close()

	callbackURL2 := resp.Header.Get("Location")
	resp, err = client.Get(callbackURL2)
	if err != nil {
		t.Fatalf("failed GET /callback for IdP 2: %v", err)
	}
	resp.Body.Close()

	cookies2 := resp.Cookies()
	if len(cookies2) == 0 {
		t.Fatal("no cookies from /callback for IdP 2")
	}

	// IdP 2 の Cookie でも認証成功
	req, _ = http.NewRequest("GET", dummySrv.URL+"/api/data", nil)
	for _, c := range cookies2 {
		req.AddCookie(c)
	}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("failed authenticated request with IdP2: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for IdP2 session, got %d", resp.StatusCode)
	}

	var body2 map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body2); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if body2["status"] != "authenticated" {
		t.Fatalf("expected authenticated for IdP2, got %s", body2["status"])
	}
}

// --- E2E 5: 未認証 API リクエスト → 401 ---

func TestIntegration_UnauthenticatedAPIRequest(t *testing.T) {
	mockIdP := testutil.NewMockIdP(t)
	authSrv, _ := setupAuth(t, mockIdP)
	defer authSrv.Close()

	client := newNoRedirectClient()

	// API リクエスト（Accept: text/html なし）→ 401
	req, _ := http.NewRequest("GET", authSrv.URL+"/api/data", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed API request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated API request, got %d", resp.StatusCode)
	}
}

// --- E2E 6: 無効な Bearer トークン → 401 ---

func TestIntegration_InvalidBearerToken(t *testing.T) {
	mockIdP := testutil.NewMockIdP(t)
	authSrv, _ := setupAuth(t, mockIdP)
	defer authSrv.Close()

	client := newNoRedirectClient()

	req, _ := http.NewRequest("GET", authSrv.URL+"/api/data", nil)
	req.Header.Set("Authorization", "Bearer invalid-token-xxx")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed invalid bearer request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid bearer, got %d", resp.StatusCode)
	}

	// WWW-Authenticate ヘッダーが設定されていることを確認
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Fatal("expected WWW-Authenticate header for invalid bearer")
	}
	if !strings.Contains(wwwAuth, "Bearer") {
		t.Fatalf("expected WWW-Authenticate to contain 'Bearer', got %s", wwwAuth)
	}
}
