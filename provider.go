package idproxy

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/url"
	"regexp"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// providerEntry は1つの OIDC プロバイダーの内部状態を保持する。
type providerEntry struct {
	config       OIDCProvider
	oidcProvider *oidc.Provider
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

// ProviderManager は複数の OIDC プロバイダーを管理する。
type ProviderManager struct {
	providers  map[string]*providerEntry // key: Issuer URL
	order      []string                  // 設定順序を保持（選択ページ用）
	pathPrefix string
	logger     *slog.Logger
}

// NewProviderManager は Config.Providers から ProviderManager を生成する。
// 各プロバイダーに対して OIDC Discovery を取得し、初期化を行う。
func NewProviderManager(ctx context.Context, cfg Config) (*ProviderManager, error) {
	if len(cfg.Providers) == 0 {
		return nil, fmt.Errorf("at least one provider is required")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	redirectURL := cfg.ExternalURL + cfg.PathPrefix + "/callback"

	pm := &ProviderManager{
		providers:  make(map[string]*providerEntry, len(cfg.Providers)),
		order:      make([]string, 0, len(cfg.Providers)),
		pathPrefix: cfg.PathPrefix,
		logger:     logger,
	}

	for _, p := range cfg.Providers {
		provider, err := oidc.NewProvider(ctx, p.Issuer)
		if err != nil {
			return nil, fmt.Errorf("failed to discover OIDC provider %q: %w", p.Issuer, err)
		}

		scopes := p.Scopes
		if len(scopes) == 0 {
			scopes = append([]string{}, DefaultScopes...)
		}

		oc := oauth2.Config{
			ClientID:     p.ClientID,
			ClientSecret: p.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  redirectURL,
			Scopes:       scopes,
		}

		verifier := provider.Verifier(&oidc.Config{
			ClientID: p.ClientID,
		})

		entry := &providerEntry{
			config:       p,
			oidcProvider: provider,
			oauth2Config: oc,
			verifier:     verifier,
		}

		pm.providers[p.Issuer] = entry
		pm.order = append(pm.order, p.Issuer)
	}

	return pm, nil
}

// Get は Issuer URL に対応するプロバイダー情報を返す。
func (pm *ProviderManager) Get(issuer string) (*providerEntry, bool) {
	entry, ok := pm.providers[issuer]
	if !ok {
		return nil, false
	}
	return entry, true
}

// List は設定順序でプロバイダー一覧を返す。
func (pm *ProviderManager) List() []OIDCProvider {
	result := make([]OIDCProvider, 0, len(pm.order))
	for _, issuer := range pm.order {
		if entry, ok := pm.providers[issuer]; ok {
			result = append(result, entry.config)
		}
	}
	return result
}

// Count はプロバイダー数を返す。
func (pm *ProviderManager) Count() int {
	return len(pm.providers)
}

// Single は単一プロバイダーの場合にそのプロバイダーを返す。
// 複数の場合は nil, false を返す。
func (pm *ProviderManager) Single() (*providerEntry, bool) {
	if len(pm.providers) != 1 {
		return nil, false
	}
	entry := pm.providers[pm.order[0]]
	return entry, true
}

// OAuth2Config は指定プロバイダーの oauth2.Config を返す。
func (pm *ProviderManager) OAuth2Config(issuer string) (*oauth2.Config, error) {
	entry, ok := pm.providers[issuer]
	if !ok {
		return nil, fmt.Errorf("provider not found: %s", issuer)
	}
	cfg := entry.oauth2Config // コピー
	return &cfg, nil
}

// Verifier は指定プロバイダーの IDTokenVerifier を返す。
func (pm *ProviderManager) Verifier(issuer string) (*oidc.IDTokenVerifier, error) {
	entry, ok := pm.providers[issuer]
	if !ok {
		return nil, fmt.Errorf("provider not found: %s", issuer)
	}
	return entry.verifier, nil
}

// selectionPageTemplate は複数プロバイダー選択ページの HTML テンプレート。
var selectionPageTemplate = template.Must(template.New("selection").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in - idproxy</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #f5f5f5; }
  .container { background: #fff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); padding: 2rem; max-width: 400px; width: 100%; }
  h1 { font-size: 1.5rem; margin: 0 0 1.5rem; text-align: center; }
  a.provider { display: block; padding: 0.75rem 1rem; margin: 0.5rem 0; background: #0066cc; color: #fff; text-decoration: none; border-radius: 4px; text-align: center; }
  a.provider:hover { background: #0055aa; }
</style>
</head>
<body>
<div class="container">
<h1>Sign in</h1>
{{range .Providers}}<a class="provider" href="{{.Link}}">{{.Name}}</a>
{{end}}</div>
</body>
</html>`))

// selectionEntry はテンプレートに渡すプロバイダー情報。
type selectionEntry struct {
	Name string
	Link string
}

// SelectionHTML は複数プロバイダー選択ページの HTML を生成する。
func (pm *ProviderManager) SelectionHTML() string {
	entries := make([]selectionEntry, 0, len(pm.order))
	for _, issuer := range pm.order {
		entry := pm.providers[issuer]
		name := resolveProviderName(entry.config)
		link := pm.pathPrefix + "/login?provider=" + url.QueryEscape(issuer)
		entries = append(entries, selectionEntry{
			Name: name,
			Link: link,
		})
	}

	var buf bytes.Buffer
	if err := selectionPageTemplate.Execute(&buf, map[string]any{
		"Providers": entries,
	}); err != nil {
		pm.logger.Error("failed to render selection page", "error", err)
		return "Internal Server Error"
	}
	return buf.String()
}

// knownIssuers は既知の OIDC Issuer ホスト名から表示名へのマッピング（完全一致）。
var knownIssuers = map[string]string{
	"accounts.google.com":       "Google",
	"login.microsoftonline.com": "Microsoft",
}

// knownIssuerPatterns はホスト名がリージョン等で動的になる Issuer の正規表現マッチ。
// 順序を保ちたいため slice。
var knownIssuerPatterns = []struct {
	re   *regexp.Regexp
	name string
}{
	// Amazon Cognito User Pool: cognito-idp.<region>.amazonaws.com
	{regexp.MustCompile(`^cognito-idp\.[a-z0-9-]+\.amazonaws\.com$`), "Amazon Cognito"},
}

// resolveProviderName は OIDCProvider の表示名を解決する。
// Name が設定されていればそれを返し、未設定の場合は Issuer URL から自動生成する。
func resolveProviderName(p OIDCProvider) string {
	if p.Name != "" {
		return p.Name
	}

	u, err := url.Parse(p.Issuer)
	if err != nil {
		return p.Issuer
	}

	host := u.Hostname()
	if name, ok := knownIssuers[host]; ok {
		return name
	}
	for _, kp := range knownIssuerPatterns {
		if kp.re.MatchString(host) {
			return kp.name
		}
	}
	return host
}
