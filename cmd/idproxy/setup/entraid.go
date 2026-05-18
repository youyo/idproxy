package setup

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// App は Entra ID のアプリ登録を表す。
type App struct {
	AppID       string // appId（= OIDC_CLIENT_ID）
	ObjectID    string // id（az ad app コマンドで使う Object ID）
	DisplayName string
}

// ErrMultipleAppsFound は同名のアプリが複数見つかった場合のエラー。
// 呼び出し側は Candidates を表示して --app-id で再指定するよう促す。
type ErrMultipleAppsFound struct {
	Candidates []App
}

func (e *ErrMultipleAppsFound) Error() string {
	names := make([]string, 0, len(e.Candidates))
	for _, a := range e.Candidates {
		names = append(names, a.AppID)
	}
	return fmt.Sprintf("multiple apps found: %s", strings.Join(names, ", "))
}

// AZClient は az CLI を CommandExecutor 経由で呼ぶラッパー。
type AZClient struct {
	Exec CommandExecutor
}

// NewAZClient は AZClient を生成する。
func NewAZClient(exec CommandExecutor) *AZClient {
	return &AZClient{Exec: exec}
}

// rawApp は az ad app の JSON レスポンスの最小スキーマ。
type rawApp struct {
	AppID       string `json:"appId"`
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

func (r rawApp) toApp() App {
	return App{AppID: r.AppID, ObjectID: r.ID, DisplayName: r.DisplayName}
}

// FindApp は displayName 完全一致でアプリを検索する。
// 0件: nil,nil / 1件: *App,nil / 2件以上: nil, *ErrMultipleAppsFound
func (c *AZClient) FindApp(ctx context.Context, displayName string) (*App, error) {
	args := []string{
		"ad", "app", "list",
		"--filter", fmt.Sprintf("displayName eq '%s'", oDataEscapeSingleQuote(displayName)),
		"--output", "json",
	}
	out, err := c.Exec.Output(ctx, "az", args)
	if err != nil {
		return nil, fmt.Errorf("az ad app list: %w", err)
	}
	var apps []rawApp
	if err := json.Unmarshal(out, &apps); err != nil {
		return nil, fmt.Errorf("parse az ad app list output: %w", err)
	}
	switch len(apps) {
	case 0:
		return nil, nil
	case 1:
		a := apps[0].toApp()
		return &a, nil
	default:
		candidates := make([]App, len(apps))
		for i, r := range apps {
			candidates[i] = r.toApp()
		}
		return nil, &ErrMultipleAppsFound{Candidates: candidates}
	}
}

// CreateApp は新しいアプリを作成する。
func (c *AZClient) CreateApp(ctx context.Context, displayName string) (*App, error) {
	args := []string{
		"ad", "app", "create",
		"--display-name", displayName,
		"--output", "json",
	}
	out, err := c.Exec.Output(ctx, "az", args)
	if err != nil {
		return nil, fmt.Errorf("az ad app create: %w", err)
	}
	var r rawApp
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, fmt.Errorf("parse az ad app create output: %w", err)
	}
	a := r.toApp()
	return &a, nil
}

// rawCredential は az ad app credential reset の JSON レスポンスの最小スキーマ。
type rawCredential struct {
	SecretText string `json:"secretText"`
	Password   string `json:"password"`
}

// ResetCredential は client_secret を再生成する。有効期限は 2 年固定。
func (c *AZClient) ResetCredential(ctx context.Context, appID string) (string, error) {
	args := []string{
		"ad", "app", "credential", "reset",
		"--id", appID,
		"--years", "2",
		"--output", "json",
	}
	out, err := c.Exec.Output(ctx, "az", args)
	if err != nil {
		return "", fmt.Errorf("az ad app credential reset: %w", err)
	}
	var r rawCredential
	if err := json.Unmarshal(out, &r); err != nil {
		return "", fmt.Errorf("parse credential reset output: %w", err)
	}
	if r.SecretText != "" {
		return r.SecretText, nil
	}
	if r.Password != "" {
		return r.Password, nil
	}
	return "", fmt.Errorf("credential reset returned empty secret")
}

// GetRedirectURIs は Web プラットフォームの redirectUris を取得する。
// null の場合は空スライス（non-nil）を返す。
func (c *AZClient) GetRedirectURIs(ctx context.Context, appID string) ([]string, error) {
	args := []string{
		"ad", "app", "show",
		"--id", appID,
		"--query", "web.redirectUris",
		"--output", "json",
	}
	out, err := c.Exec.Output(ctx, "az", args)
	if err != nil {
		return nil, fmt.Errorf("az ad app show: %w", err)
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "null" {
		return []string{}, nil
	}
	var uris []string
	if err := json.Unmarshal(out, &uris); err != nil {
		return nil, fmt.Errorf("parse redirect URIs: %w", err)
	}
	if uris == nil {
		uris = []string{}
	}
	return uris, nil
}

// SetRedirectURIs は Web プラットフォームの redirectUris を上書きする。
// uris が空の場合は az を呼ばずに nil を返す（意味のない呼び出しを避ける）。
func (c *AZClient) SetRedirectURIs(ctx context.Context, appID string, uris []string) error {
	if len(uris) == 0 {
		return nil
	}
	args := []string{
		"ad", "app", "update",
		"--id", appID,
		"--web-redirect-uris",
	}
	args = append(args, uris...)
	if _, err := c.Exec.Output(ctx, "az", args); err != nil {
		return fmt.Errorf("az ad app update: %w", err)
	}
	return nil
}

// AddRequiredPermissions は Entra ID アプリに OIDC で必要な Microsoft Graph の
// delegated permission（openid / email / profile / offline_access）を追加する。
// 既に存在する場合は no-op（az は冪等）。
// offline_access を含めることで IdP が refresh_token を返すようになる。
func (c *AZClient) AddRequiredPermissions(ctx context.Context, appID string) error {
	// Microsoft Graph (00000003-0000-0000-c000-000000000000) のスコープ:
	//   openid        : 37f7f235-527c-4136-accd-4a02d197296e
	//   email         : 64a6cdd6-aab1-4aaf-94b8-3cc8405e90d6
	//   profile       : 14dad69e-099b-42c9-810b-d002981feec1
	//   offline_access: 7427e0e9-2fba-42fe-b0c0-848c9e6a8182
	args := []string{
		"ad", "app", "permission", "add",
		"--id", appID,
		"--api", "00000003-0000-0000-c000-000000000000",
		"--api-permissions",
		"37f7f235-527c-4136-accd-4a02d197296e=Scope",
		"64a6cdd6-aab1-4aaf-94b8-3cc8405e90d6=Scope",
		"14dad69e-099b-42c9-810b-d002981feec1=Scope",
		"7427e0e9-2fba-42fe-b0c0-848c9e6a8182=Scope",
	}
	if _, err := c.Exec.Output(ctx, "az", args); err != nil {
		return fmt.Errorf("az ad app permission add (required permissions): %w", err)
	}
	return nil
}

// oDataEscapeSingleQuote は OData フィルタ文字列のシングルクオートをエスケープする。
// OData の慣例: シングルクオートは '' に置換する。
func oDataEscapeSingleQuote(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// GetTenantID は現在ログイン中のテナント ID を返す。
func (c *AZClient) GetTenantID(ctx context.Context) (string, error) {
	args := []string{"account", "show", "--query", "tenantId", "--output", "json"}
	out, err := c.Exec.Output(ctx, "az", args)
	if err != nil {
		return "", fmt.Errorf("az account show: %w", err)
	}
	var tid string
	if err := json.Unmarshal(out, &tid); err != nil {
		return "", fmt.Errorf("parse tenantId: %w", err)
	}
	return tid, nil
}
