package idproxy

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/youyo/idproxy/testutil"
)

// --- ヘルパー ---

// setupSingleProvider は単一 MockIdP で ProviderManager を構築するヘルパー。
func setupSingleProvider(t *testing.T) (*ProviderManager, *testutil.MockIdP) {
	t.Helper()
	idp := testutil.NewMockIdP(t)
	cfg := Config{
		Providers: []OIDCProvider{
			{
				Issuer:       idp.Issuer(),
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		},
		ExternalURL:  "http://localhost:8080",
		CookieSecret: make([]byte, 32),
		PathPrefix:   "/auth",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	pm, err := NewProviderManager(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewProviderManager: %v", err)
	}
	return pm, idp
}

// setupMultipleProviders は2つの MockIdP で ProviderManager を構築するヘルパー。
func setupMultipleProviders(t *testing.T) (*ProviderManager, *testutil.MockIdP, *testutil.MockIdP) {
	t.Helper()
	idp1 := testutil.NewMockIdP(t)
	idp2 := testutil.NewMockIdP(t)
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
		CookieSecret: make([]byte, 32),
		PathPrefix:   "/auth",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	pm, err := NewProviderManager(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewProviderManager: %v", err)
	}
	return pm, idp1, idp2
}

// --- サイクル 1: NewProviderManager 基本初期化 ---

// T01: 単一プロバイダー初期化成功
func TestNewProviderManager_SingleProvider(t *testing.T) {
	pm, _ := setupSingleProvider(t)
	if pm.Count() != 1 {
		t.Errorf("Count() = %d, want 1", pm.Count())
	}
}

// T02: 複数プロバイダー初期化成功
func TestNewProviderManager_MultipleProviders(t *testing.T) {
	pm, _, _ := setupMultipleProviders(t)
	if pm.Count() != 2 {
		t.Errorf("Count() = %d, want 2", pm.Count())
	}
}

// --- サイクル 2: プロバイダー取得 ---

// T03: Get で既存プロバイダー取得
func TestProviderManager_Get_Exists(t *testing.T) {
	pm, idp := setupSingleProvider(t)
	entry, ok := pm.Get(idp.Issuer())
	if !ok {
		t.Fatal("Get returned ok=false for existing provider")
	}
	if entry == nil {
		t.Fatal("Get returned nil entry for existing provider")
	}
}

// T04: Get で未存在プロバイダー
func TestProviderManager_Get_NotExists(t *testing.T) {
	pm, _ := setupSingleProvider(t)
	entry, ok := pm.Get("https://nonexistent.example.com")
	if ok {
		t.Error("Get returned ok=true for non-existing provider")
	}
	if entry != nil {
		t.Error("Get returned non-nil entry for non-existing provider")
	}
}

// T05: List で設定順序を保持
func TestProviderManager_List_Order(t *testing.T) {
	pm, idp1, idp2 := setupMultipleProviders(t)
	list := pm.List()
	if len(list) != 2 {
		t.Fatalf("List() length = %d, want 2", len(list))
	}
	if list[0].Issuer != idp1.Issuer() {
		t.Errorf("List()[0].Issuer = %s, want %s", list[0].Issuer, idp1.Issuer())
	}
	if list[1].Issuer != idp2.Issuer() {
		t.Errorf("List()[1].Issuer = %s, want %s", list[1].Issuer, idp2.Issuer())
	}
}

// T06: Single: 1プロバイダー
func TestProviderManager_Single_OneProvider(t *testing.T) {
	pm, _ := setupSingleProvider(t)
	entry, ok := pm.Single()
	if !ok {
		t.Fatal("Single returned ok=false for single provider")
	}
	if entry == nil {
		t.Fatal("Single returned nil entry for single provider")
	}
}

// T07: Single: 複数プロバイダー
func TestProviderManager_Single_MultipleProviders(t *testing.T) {
	pm, _, _ := setupMultipleProviders(t)
	entry, ok := pm.Single()
	if ok {
		t.Error("Single returned ok=true for multiple providers")
	}
	if entry != nil {
		t.Error("Single returned non-nil entry for multiple providers")
	}
}

// --- サイクル 3: OAuth2Config / Verifier 取得 ---

// T08: OAuth2Config 取得成功
func TestProviderManager_OAuth2Config_Success(t *testing.T) {
	pm, idp := setupSingleProvider(t)
	oc, err := pm.OAuth2Config(idp.Issuer())
	if err != nil {
		t.Fatalf("OAuth2Config: %v", err)
	}
	if oc.ClientID != "test-client-id" {
		t.Errorf("ClientID = %s, want test-client-id", oc.ClientID)
	}
	if oc.ClientSecret != "test-client-secret" {
		t.Errorf("ClientSecret = %s, want test-client-secret", oc.ClientSecret)
	}
	wantRedirect := "http://localhost:8080/auth/callback"
	if oc.RedirectURL != wantRedirect {
		t.Errorf("RedirectURL = %s, want %s", oc.RedirectURL, wantRedirect)
	}
	// デフォルトスコープを確認
	wantScopes := []string{"openid", "email", "profile"}
	if len(oc.Scopes) != len(wantScopes) {
		t.Fatalf("Scopes length = %d, want %d", len(oc.Scopes), len(wantScopes))
	}
	for i, s := range oc.Scopes {
		if s != wantScopes[i] {
			t.Errorf("Scopes[%d] = %s, want %s", i, s, wantScopes[i])
		}
	}
}

// T09: OAuth2Config 未存在 Issuer
func TestProviderManager_OAuth2Config_NotExists(t *testing.T) {
	pm, _ := setupSingleProvider(t)
	_, err := pm.OAuth2Config("https://nonexistent.example.com")
	if err == nil {
		t.Error("OAuth2Config should return error for non-existing issuer")
	}
}

// T10: Verifier 取得成功
func TestProviderManager_Verifier_Success(t *testing.T) {
	pm, idp := setupSingleProvider(t)
	v, err := pm.Verifier(idp.Issuer())
	if err != nil {
		t.Fatalf("Verifier: %v", err)
	}
	if v == nil {
		t.Fatal("Verifier returned nil")
	}
}

// T11: Verifier 未存在 Issuer
func TestProviderManager_Verifier_NotExists(t *testing.T) {
	pm, _ := setupSingleProvider(t)
	_, err := pm.Verifier("https://nonexistent.example.com")
	if err == nil {
		t.Error("Verifier should return error for non-existing issuer")
	}
}

// T12: デフォルトスコープの適用
func TestProviderManager_DefaultScopes(t *testing.T) {
	pm, idp := setupSingleProvider(t)
	oc, err := pm.OAuth2Config(idp.Issuer())
	if err != nil {
		t.Fatalf("OAuth2Config: %v", err)
	}
	wantScopes := []string{"openid", "email", "profile"}
	if len(oc.Scopes) != len(wantScopes) {
		t.Fatalf("Scopes length = %d, want %d", len(oc.Scopes), len(wantScopes))
	}
	for i, s := range oc.Scopes {
		if s != wantScopes[i] {
			t.Errorf("Scopes[%d] = %s, want %s", i, s, wantScopes[i])
		}
	}
}

// --- サイクル 4: プロバイダー名自動生成 ---

// T13: Name 指定あり
func TestResolveProviderName_Explicit(t *testing.T) {
	p := OIDCProvider{
		Issuer: "https://example.com",
		Name:   "My IdP",
	}
	got := resolveProviderName(p)
	if got != "My IdP" {
		t.Errorf("resolveProviderName = %s, want My IdP", got)
	}
}

// T14: Name 未指定 - Google
func TestResolveProviderName_Google(t *testing.T) {
	p := OIDCProvider{
		Issuer: "https://accounts.google.com",
	}
	got := resolveProviderName(p)
	if got != "Google" {
		t.Errorf("resolveProviderName = %s, want Google", got)
	}
}

// T15: Name 未指定 - Microsoft
func TestResolveProviderName_Microsoft(t *testing.T) {
	p := OIDCProvider{
		Issuer: "https://login.microsoftonline.com/tenant-id/v2.0",
	}
	got := resolveProviderName(p)
	if got != "Microsoft" {
		t.Errorf("resolveProviderName = %s, want Microsoft", got)
	}
}

// T15b: Name 未指定 - Amazon Cognito (リージョン違い)
func TestResolveProviderName_Cognito(t *testing.T) {
	cases := []string{
		"https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123",
		"https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_xyz",
		"https://cognito-idp.eu-west-2.amazonaws.com/eu-west-2_AbCdEf",
	}
	for _, issuer := range cases {
		got := resolveProviderName(OIDCProvider{Issuer: issuer})
		if got != "Amazon Cognito" {
			t.Errorf("resolveProviderName(%q) = %q, want Amazon Cognito", issuer, got)
		}
	}
}

// T16: Name 未指定 - 未知
func TestResolveProviderName_Unknown(t *testing.T) {
	p := OIDCProvider{
		Issuer: "https://auth.mycompany.com/realms/main",
	}
	got := resolveProviderName(p)
	if got != "auth.mycompany.com" {
		t.Errorf("resolveProviderName = %s, want auth.mycompany.com", got)
	}
}

// --- サイクル 5: 選択ページ HTML 生成 ---

// T17: 複数プロバイダーの HTML 生成
func TestProviderManager_SelectionHTML_ContainsProviderNames(t *testing.T) {
	idp1 := testutil.NewMockIdP(t)
	idp2 := testutil.NewMockIdP(t)
	cfg := Config{
		Providers: []OIDCProvider{
			{
				Issuer:       idp1.Issuer(),
				ClientID:     "client-1",
				ClientSecret: "secret-1",
				Name:         "Provider Alpha",
			},
			{
				Issuer:       idp2.Issuer(),
				ClientID:     "client-2",
				ClientSecret: "secret-2",
				Name:         "Provider Beta",
			},
		},
		ExternalURL:  "http://localhost:8080",
		CookieSecret: make([]byte, 32),
		PathPrefix:   "/auth",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	pm, err := NewProviderManager(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewProviderManager: %v", err)
	}

	html := pm.SelectionHTML()
	if !strings.Contains(html, "Provider Alpha") {
		t.Error("SelectionHTML does not contain 'Provider Alpha'")
	}
	if !strings.Contains(html, "Provider Beta") {
		t.Error("SelectionHTML does not contain 'Provider Beta'")
	}
}

// T18: HTML に Issuer がパラメータとして含まれる
func TestProviderManager_SelectionHTML_ContainsProviderLinks(t *testing.T) {
	idp1 := testutil.NewMockIdP(t)
	idp2 := testutil.NewMockIdP(t)
	cfg := Config{
		Providers: []OIDCProvider{
			{
				Issuer:       idp1.Issuer(),
				ClientID:     "client-1",
				ClientSecret: "secret-1",
				Name:         "Provider One",
			},
			{
				Issuer:       idp2.Issuer(),
				ClientID:     "client-2",
				ClientSecret: "secret-2",
				Name:         "Provider Two",
			},
		},
		ExternalURL:  "http://localhost:8080",
		CookieSecret: make([]byte, 32),
		PathPrefix:   "/auth",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	pm, err := NewProviderManager(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewProviderManager: %v", err)
	}

	html := pm.SelectionHTML()
	// リンク先が /auth/login?provider=<url-encoded-issuer> 形式であること
	wantLink1 := "/auth/login?provider=" + url.QueryEscape(idp1.Issuer())
	wantLink2 := "/auth/login?provider=" + url.QueryEscape(idp2.Issuer())
	if !strings.Contains(html, wantLink1) {
		t.Errorf("SelectionHTML does not contain link %s", wantLink1)
	}
	if !strings.Contains(html, wantLink2) {
		t.Errorf("SelectionHTML does not contain link %s", wantLink2)
	}
}

// T19: HTML が有効な HTML5
func TestProviderManager_SelectionHTML_ValidHTML5(t *testing.T) {
	pm, _, _ := setupMultipleProviders(t)
	html := pm.SelectionHTML()
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("SelectionHTML does not contain DOCTYPE")
	}
	if !strings.Contains(html, "<html") {
		t.Error("SelectionHTML does not contain <html>")
	}
	if !strings.Contains(html, "<head>") {
		t.Error("SelectionHTML does not contain <head>")
	}
	if !strings.Contains(html, "<body>") {
		t.Error("SelectionHTML does not contain <body>")
	}
}

// --- サイクル 6: エラーケース ---

// T20: Discovery 取得失敗
func TestNewProviderManager_DiscoveryFailure(t *testing.T) {
	// 即座に閉じるサーバーで接続不能にする
	ts := httptest.NewServer(nil)
	badURL := ts.URL
	ts.Close()

	cfg := Config{
		Providers: []OIDCProvider{
			{
				Issuer:       badURL,
				ClientID:     "client",
				ClientSecret: "secret",
			},
		},
		ExternalURL:  "http://localhost:8080",
		CookieSecret: make([]byte, 32),
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	_, err := NewProviderManager(context.Background(), cfg)
	if err == nil {
		t.Fatal("NewProviderManager should return error for unreachable issuer")
	}
	if !strings.Contains(err.Error(), "failed to discover") {
		t.Errorf("error message should contain 'failed to discover', got: %s", err.Error())
	}
}

// T21: プロバイダーリスト空
func TestNewProviderManager_EmptyProviders(t *testing.T) {
	cfg := Config{
		Providers:    []OIDCProvider{},
		ExternalURL:  "http://localhost:8080",
		CookieSecret: make([]byte, 32),
	}
	// Validate() でエラーになるが、NewProviderManager でもガードする
	_, err := NewProviderManager(context.Background(), cfg)
	if err == nil {
		t.Fatal("NewProviderManager should return error for empty providers")
	}
}

// T22: コンテキストキャンセル
func TestNewProviderManager_CancelledContext(t *testing.T) {
	idp := testutil.NewMockIdP(t)
	cfg := Config{
		Providers: []OIDCProvider{
			{
				Issuer:       idp.Issuer(),
				ClientID:     "client",
				ClientSecret: "secret",
			},
		},
		ExternalURL:  "http://localhost:8080",
		CookieSecret: make([]byte, 32),
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 即座にキャンセル

	_, err := NewProviderManager(ctx, cfg)
	if err == nil {
		t.Fatal("NewProviderManager should return error for cancelled context")
	}
}
