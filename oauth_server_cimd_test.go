package idproxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// --- CIMD 経路の /authorize・/token 統合テスト ---

// setupCIMDServer は CIMD テストサーバーに到達できる OAuthServer を構築する。
// staticClientID が空文字なら OAuthConfig.ClientID 未設定の構成になる
// （この構成では未知の client_id が isAllowedRedirectURI のデフォルト許可へ落ちるため、
// CIMD の fail-closed を検証する対象になる）。
func setupCIMDServer(t *testing.T, ts *cimdTestServer, staticClientID string) (*OAuthServer, *SessionManager) {
	t.Helper()

	return setupCIMDServerWithConfig(t, ts, staticClientID, func(o *OAuthConfig) {
		// CIMD はデフォルト無効なので、CIMD 経路を検証するテストでは明示的に有効化する。
		o.AllowCIMDClients = true
	})
}

// setupCIMDServerWithConfig は OAuthConfig を customize してから OAuthServer を構築する。
func setupCIMDServerWithConfig(t *testing.T, ts *cimdTestServer, staticClientID string, customize func(*OAuthConfig)) (*OAuthServer, *SessionManager) {
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
		Store:        st,
		OAuth: &OAuthConfig{
			SigningKey: privateKey,
			ClientID:   staticClientID,
		},
	}
	if customize != nil {
		customize(cfg.OAuth)
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate() failed: %v", err)
	}

	sm, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("NewSessionManager() failed: %v", err)
	}

	srv, err := NewOAuthServer(cfg, st, sm, nil)
	if err != nil {
		t.Fatalf("NewOAuthServer() failed: %v", err)
	}

	// 本番の fetcher は loopback を拒否するため、テストサーバーに到達できる
	// fetcher へ差し替える（本番コードにテスト専用の分岐は置かない）。
	srv.cimd = newTestCIMDFetcher(t, ts)

	return srv, sm
}

// cimdAuthorizeQuery は CIMD client_id を使う /authorize クエリを返す。
func cimdAuthorizeQuery(clientID string) url.Values {
	q := validAuthorizeQuery()
	q.Set("client_id", clientID)
	return q
}

// TestOAuthServer_MetadataAdvertisesCIMD は AS メタデータが CIMD サポートを広告することを検証する。
func TestOAuthServer_MetadataAdvertisesCIMD(t *testing.T) {
	srv := setupOAuthServer(t, "http://localhost:8080", "")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var meta map[string]any
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("failed to decode AS metadata: %v", err)
	}
	if got, ok := meta["client_id_metadata_document_supported"].(bool); !ok || !got {
		t.Errorf("expected client_id_metadata_document_supported=true, got %v", meta["client_id_metadata_document_supported"])
	}
}

// TestOAuthServer_AuthorizeWithCIMDClient は CIMD で解決した metadata の
// redirect_uris と認可リクエストの redirect_uri が照合されることを検証する。
func TestOAuthServer_AuthorizeWithCIMDClient(t *testing.T) {
	ts := newCIMDDocumentServer(t, validCIMDDocument())

	for _, staticClientID := range []string{"test-oauth-client", ""} {
		name := "static client_id set"
		if staticClientID == "" {
			name = "static client_id unset"
		}
		t.Run(name, func(t *testing.T) {
			srv, sm := setupCIMDServer(t, ts, staticClientID)
			clientID := ts.clientID("/client.json")

			locURL := authorizeWithSession(t, srv, sm, cimdAuthorizeQuery(clientID))
			if locURL.Query().Get("code") == "" {
				t.Errorf("expected authorization code in redirect, got %q", locURL.String())
			}
		})
	}
}

// TestOAuthServer_AuthorizeCIMDDisabledByDefault は AllowCIMDClients 未設定のとき
// CIMD 形式 client_id が invalid_client 400 になり、fetch も発行されないことを検証する。
func TestOAuthServer_AuthorizeCIMDDisabledByDefault(t *testing.T) {
	for _, staticClientID := range []string{"test-oauth-client", ""} {
		name := "static client_id set"
		if staticClientID == "" {
			name = "static client_id unset"
		}
		t.Run(name, func(t *testing.T) {
			ts := newCIMDDocumentServer(t, validCIMDDocument())
			srv, sm := setupCIMDServerWithConfig(t, ts, staticClientID, nil)

			q := cimdAuthorizeQuery(ts.clientID("/client.json"))
			req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
			for _, c := range issueTestSession(t, sm) {
				req.AddCookie(c)
			}
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected %d, got %d; body: %s", http.StatusBadRequest, w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "invalid_client") {
				t.Errorf("expected invalid_client error, got %s", w.Body.String())
			}
			if got := ts.fetches.Load(); got != 0 {
				t.Errorf("expected no CIMD fetch when disabled, got %d", got)
			}
		})
	}
}

// TestOAuthServer_AuthorizeCIMDHostAllowlist は AllowedCIMDHosts に無いホストの
// client_id が fetch されずに拒否されることを検証する。
func TestOAuthServer_AuthorizeCIMDHostAllowlist(t *testing.T) {
	ts := newCIMDDocumentServer(t, validCIMDDocument())
	srv, sm := setupCIMDServerWithConfig(t, ts, "test-oauth-client", func(o *OAuthConfig) {
		o.AllowCIMDClients = true
		o.AllowedCIMDHosts = []string{"trusted.example.com"}
	})

	q := cimdAuthorizeQuery(ts.clientID("/client.json"))
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	for _, c := range issueTestSession(t, sm) {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d; body: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid_client") {
		t.Errorf("expected invalid_client error, got %s", w.Body.String())
	}
	if got := ts.fetches.Load(); got != 0 {
		t.Errorf("expected no CIMD fetch for disallowed host, got %d", got)
	}
}

// TestOAuthServer_AuthorizeCIMDRespectsOperatorAllowlist は、metadata document の
// redirect_uris に含まれていても運用者の AllowedRedirectURIs を通らない
// redirect_uri が拒否されることを検証する（同意画面が無いことへの最終防衛線）。
func TestOAuthServer_AuthorizeCIMDRespectsOperatorAllowlist(t *testing.T) {
	doc := validCIMDDocument()
	doc["redirect_uris"] = []string{"https://evil.example.com/cb"}
	ts := newCIMDDocumentServer(t, doc)

	srv, sm := setupCIMDServerWithConfig(t, ts, "test-oauth-client", func(o *OAuthConfig) {
		o.AllowCIMDClients = true
		o.AllowedRedirectURIs = []string{"https://app.example.com/callback"}
	})

	q := cimdAuthorizeQuery(ts.clientID("/client.json"))
	q.Set("redirect_uri", "https://evil.example.com/cb")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	for _, c := range issueTestSession(t, sm) {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d; body: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid_request") {
		t.Errorf("expected invalid_request error, got %s", w.Body.String())
	}
}

// TestOAuthServer_AuthorizeCIMDRedirectURIMismatch は metadata の redirect_uris に
// 含まれない redirect_uri を拒否することを検証する。
func TestOAuthServer_AuthorizeCIMDRedirectURIMismatch(t *testing.T) {
	ts := newCIMDDocumentServer(t, validCIMDDocument())
	srv, sm := setupCIMDServer(t, ts, "test-oauth-client")

	q := cimdAuthorizeQuery(ts.clientID("/client.json"))
	q.Set("redirect_uri", "http://localhost:3000/evil")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	for _, c := range issueTestSession(t, sm) {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d; body: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
}

// TestOAuthServer_AuthorizeCIMDFailClosed は CIMD の fetch / 検証が失敗したとき
// invalid_client 400 で打ち切ることを検証する。特に静的 ClientID 未設定の構成でも
// isAllowedRedirectURI のデフォルト許可経路へ落ちないことを固定する（fail-closed）。
func TestOAuthServer_AuthorizeCIMDFailClosed(t *testing.T) {
	docs := map[string]map[string]any{
		"client_id mismatch": {
			"client_id":     "https://attacker.example.com/client.json",
			"redirect_uris": []string{"http://localhost:3000/callback"},
		},
		"redirect_uris missing": {"client_name": "No Redirect App"},
	}

	for docName, doc := range docs {
		for _, staticClientID := range []string{"test-oauth-client", ""} {
			name := docName + "/static client_id set"
			if staticClientID == "" {
				name = docName + "/static client_id unset"
			}
			t.Run(name, func(t *testing.T) {
				ts := newCIMDDocumentServer(t, doc)
				srv, sm := setupCIMDServer(t, ts, staticClientID)

				// redirect_uri は localhost なので、CIMD 経路が抜けると
				// デフォルト許可で認可が通ってしまう。
				q := cimdAuthorizeQuery(ts.clientID("/client.json"))

				req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
				for _, c := range issueTestSession(t, sm) {
					req.AddCookie(c)
				}
				w := httptest.NewRecorder()
				srv.ServeHTTP(w, req)

				if w.Code != http.StatusBadRequest {
					t.Fatalf("expected %d, got %d; body: %s", http.StatusBadRequest, w.Code, w.Body.String())
				}
				if !strings.Contains(w.Body.String(), "invalid_client") {
					t.Errorf("expected invalid_client error, got %s", w.Body.String())
				}
			})
		}
	}
}

// TestOAuthServer_AuthorizeCIMDUnreachable は metadata を取得できない client_id が
// invalid_client 400 になることを検証する。
func TestOAuthServer_AuthorizeCIMDUnreachable(t *testing.T) {
	ts := newCIMDTestServer(t, func(w http.ResponseWriter, _ *http.Request, _ int64) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	srv, sm := setupCIMDServer(t, ts, "")

	q := cimdAuthorizeQuery(ts.clientID("/client.json"))

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	for _, c := range issueTestSession(t, sm) {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d; body: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid_client") {
		t.Errorf("expected invalid_client error, got %s", w.Body.String())
	}
}

// TestOAuthServer_AuthorizeCIMDCachedAcrossRequests は同一 client_id への 2 回目の
// /authorize で HTTP fetch が再発行されないことを検証する。
func TestOAuthServer_AuthorizeCIMDCachedAcrossRequests(t *testing.T) {
	ts := newCIMDDocumentServer(t, validCIMDDocument())
	srv, sm := setupCIMDServer(t, ts, "test-oauth-client")

	q := cimdAuthorizeQuery(ts.clientID("/client.json"))
	authorizeWithSession(t, srv, sm, q)
	authorizeWithSession(t, srv, sm, q)

	if got := ts.fetches.Load(); got != 1 {
		t.Errorf("expected 1 CIMD fetch across 2 authorize requests, got %d", got)
	}
}

// TestOAuthServer_AuthorizeNonCIMDClientIDUsesDCR は DCR で登録した UUID 形式の
// client_id が CIMD 経路に入らず従来どおり動くことを検証する（後方互換の回帰）。
func TestOAuthServer_AuthorizeNonCIMDClientIDUsesDCR(t *testing.T) {
	ts := newCIMDDocumentServer(t, validCIMDDocument())
	srv, sm := setupCIMDServer(t, ts, "test-oauth-client")

	const redirectURI = "http://localhost:3000/callback"
	body, _ := json.Marshal(map[string]any{
		"redirect_uris": []string{redirectURI},
		"client_name":   "DCR App",
	})
	regReq := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	srv.ServeHTTP(regW, regReq)
	if regW.Code != http.StatusCreated {
		t.Fatalf("expected 201 for /register, got %d: %s", regW.Code, regW.Body.String())
	}
	var regResp map[string]any
	if err := json.NewDecoder(regW.Body).Decode(&regResp); err != nil {
		t.Fatalf("failed to decode register response: %v", err)
	}
	clientID, _ := regResp["client_id"].(string)
	if isCIMDClientID(clientID) {
		t.Fatalf("DCR client_id %q must not be a CIMD client_id", clientID)
	}

	locURL := authorizeWithSession(t, srv, sm, cimdAuthorizeQuery(clientID))
	if locURL.Query().Get("code") == "" {
		t.Errorf("expected authorization code in redirect, got %q", locURL.String())
	}
	if got := ts.fetches.Load(); got != 0 {
		t.Errorf("expected no CIMD fetch for DCR client_id, got %d", got)
	}
}

// TestOAuthServer_AuthorizeHTTPClientIDNotTreatedAsCIMD は http スキームや
// path を持たない https URL が CIMD 経路に入らないことを検証する。
func TestOAuthServer_AuthorizeHTTPClientIDNotTreatedAsCIMD(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
	}{
		{"http scheme", "http://example.com/client.json"},
		{"https without path", "https://example.com"},
		{"https with root path only", "https://example.com/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newCIMDDocumentServer(t, validCIMDDocument())
			srv, sm := setupCIMDServer(t, ts, "test-oauth-client")

			req := httptest.NewRequest(http.MethodGet, "/authorize?"+cimdAuthorizeQuery(tt.clientID).Encode(), nil)
			for _, c := range issueTestSession(t, sm) {
				req.AddCookie(c)
			}
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected %d (unknown client_id), got %d; body: %s", http.StatusBadRequest, w.Code, w.Body.String())
			}
			if got := ts.fetches.Load(); got != 0 {
				t.Errorf("expected no CIMD fetch, got %d", got)
			}
		})
	}
}

// TestOAuthServer_CIMDTokenExchange は CIMD 由来の client_id で
// authorization_code 交換と refresh_token rotation が通ることを検証する。
func TestOAuthServer_CIMDTokenExchange(t *testing.T) {
	ts := newCIMDDocumentServer(t, validCIMDDocument())
	srv, sm := setupCIMDServer(t, ts, "test-oauth-client")
	clientID := ts.clientID("/client.json")

	locURL := authorizeWithSession(t, srv, sm, cimdAuthorizeQuery(clientID))
	code := locURL.Query().Get("code")
	if code == "" {
		t.Fatalf("expected authorization code, got %q", locURL.String())
	}

	// code_verifier は validAuthorizeQuery の code_challenge に対応する（RFC 7636 Appendix B）。
	tokenResp := postCIMDToken(t, srv, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"client_id":     {clientID},
		"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
	})

	refreshToken, _ := tokenResp["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatalf("expected refresh_token in token response, got %v", tokenResp)
	}

	refreshResp := postCIMDToken(t, srv, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	})
	if at, _ := refreshResp["access_token"].(string); at == "" {
		t.Errorf("expected access_token from refresh, got %v", refreshResp)
	}
}

// postCIMDToken は /token へフォームを POST し、200 応答の JSON を返す。
func postCIMDToken(t *testing.T, srv *OAuthServer, form url.Values) map[string]any {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from /token, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}
	return resp
}
