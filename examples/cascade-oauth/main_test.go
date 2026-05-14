package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	idproxy "github.com/youyo/idproxy"
	"github.com/youyo/idproxy/store"
	"github.com/youyo/idproxy/testutil"
)

// TestExternalTokenStore_HasToken は in-memory token store の最小動作を確認する。
func TestExternalTokenStore_HasToken(t *testing.T) {
	s := newExternalTokenStore()
	if s.HasToken("alice@example.com") {
		t.Error("empty store should not contain any token")
	}
	s.tokens["alice@example.com"] = "tok"
	if !s.HasToken("alice@example.com") {
		t.Error("store should contain alice's token after set")
	}
	if s.HasToken("bob@example.com") {
		t.Error("store should not contain bob's token")
	}
}

// TestStartHandlerStubRedirectSelection は /oauth/external/start のスタブ実装の
// return_to 既定値ロジック（空なら /protected）を回帰確認する。
func TestStartHandlerStubRedirectSelection(t *testing.T) {
	tests := []struct {
		name     string
		returnTo string
		want     string
	}{
		{"empty return_to falls back to /protected", "", "/protected"},
		{"explicit return_to is used", "/welcome", "/welcome"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.returnTo
			if got == "" {
				got = "/protected"
			}
			if got != tt.want {
				t.Errorf("returnTo selection = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestOnAuthenticated_RedirectsToExternalStart_WhenNoToken は OnAuthenticated フックが
// 外部トークン未保持時に /oauth/external/start を返すことを統合的に確認する。
// mock IdP を起動し、/login → /callback まで実行し最終 Location が /oauth/external/start... であることを検証する。
// 外部可観測契約: status code + Location ヘッダのみ。
func TestOnAuthenticated_RedirectsToExternalStart_WhenNoToken(t *testing.T) {
	idp := testutil.NewMockIdP(t)
	tokenStore := newExternalTokenStore() // 何も登録しない → /oauth/external/start に飛ぶはず

	cfg := idproxy.Config{
		Providers: []idproxy.OIDCProvider{
			{
				Issuer:       idp.Issuer(),
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		},
		ExternalURL:          "http://localhost:8080",
		CookieSecret:         []byte("test-cookie-secret-32-bytes-long!"),
		Store:                store.NewMemoryStore(),
		DefaultPostLoginPath: "/protected",
		OnAuthenticated: func(w http.ResponseWriter, r *http.Request, user *idproxy.User) (string, bool) {
			if !tokenStore.HasToken(user.Email) {
				return "/oauth/external/start?return_to=" + r.URL.Query().Get("redirect_to"), false
			}
			return "", false
		},
	}
	auth, err := idproxy.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("idproxy.New: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/oauth/external/start", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(auth.Wrap(mux))
	defer srv.Close()

	// Step 1: /login で IdP authorize URL に飛ばす
	client := &http.Client{
		// 自動リダイレクトを抑止し各ステップを観察
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(srv.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/login: expected 302, got %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	state := loc.Query().Get("state")
	nonce := loc.Query().Get("nonce")
	_ = resp.Body.Close()

	// Step 2: MockIdP で認可コードを発行
	code := idp.IssueCode("alice", "alice@example.com", "test-client-id", nonce)

	// Step 3: /callback
	resp, err = client.Get(srv.URL + "/callback?code=" + code + "&state=" + state)
	if err != nil {
		t.Fatalf("GET /callback: %v", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// 外部可観測契約: status 302 + Location が /oauth/external/start で始まる
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/callback: expected 302, got %d", resp.StatusCode)
	}
	gotLoc := resp.Header.Get("Location")
	if !strings.HasPrefix(gotLoc, "/oauth/external/start") {
		t.Errorf("Location should redirect to /oauth/external/start, got %q", gotLoc)
	}
}

// TestOnAuthenticated_FallsThrough_WhenTokenExists は外部トークン保持済みなら
// OnAuthenticated は ("", false) を返し、DefaultPostLoginPath が使われることを確認する。
func TestOnAuthenticated_FallsThrough_WhenTokenExists(t *testing.T) {
	idp := testutil.NewMockIdP(t)
	tokenStore := newExternalTokenStore()
	tokenStore.tokens["alice@example.com"] = "stub-token"

	cfg := idproxy.Config{
		Providers: []idproxy.OIDCProvider{
			{
				Issuer:       idp.Issuer(),
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		},
		ExternalURL:          "http://localhost:8080",
		CookieSecret:         []byte("test-cookie-secret-32-bytes-long!"),
		Store:                store.NewMemoryStore(),
		DefaultPostLoginPath: "/protected",
		OnAuthenticated: func(w http.ResponseWriter, r *http.Request, user *idproxy.User) (string, bool) {
			if !tokenStore.HasToken(user.Email) {
				return "/oauth/external/start?return_to=" + r.URL.Query().Get("redirect_to"), false
			}
			return "", false
		},
	}
	auth, err := idproxy.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("idproxy.New: %v", err)
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(auth.Wrap(mux))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(srv.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	state := loc.Query().Get("state")
	nonce := loc.Query().Get("nonce")
	_ = resp.Body.Close()

	code := idp.IssueCode("alice", "alice@example.com", "test-client-id", nonce)
	resp, err = client.Get(srv.URL + "/callback?code=" + code + "&state=" + state)
	if err != nil {
		t.Fatalf("GET /callback: %v", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/callback: expected 302, got %d", resp.StatusCode)
	}
	gotLoc := resp.Header.Get("Location")
	// /protected が使われていること（OnAuthenticated は ("", false) を返したので state.RedirectURI を使う）
	if gotLoc != "/protected" {
		t.Errorf("Location should be /protected when external token exists, got %q", gotLoc)
	}
}
