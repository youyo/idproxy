package idproxy

import (
	"crypto"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config は idproxy の設定を保持する。
type Config struct {
	// Providers は OIDC プロバイダーのリスト（1つ以上必須）。
	Providers []OIDCProvider

	// AllowedDomains は許可するメールドメインのリスト。
	// 空の場合、ドメインによる制限なし。
	AllowedDomains []string

	// AllowedEmails は許可する個別メールアドレスのリスト。
	// AllowedDomains と OR 条件で評価される。
	AllowedEmails []string

	// ExternalURL はこのサービスの外部公開 URL。
	// OAuth コールバック URL やメタデータの issuer として使用される。
	// 例: "https://mcp-auth.example.com"
	ExternalURL string

	// CookieSecret は Cookie 暗号化用の秘密鍵（32バイト以上）。
	CookieSecret []byte

	// OAuth は OAuth 2.1 AS の設定。
	// nil の場合、OAuth 2.1 AS エンドポイントは無効化される
	//（ブラウザベース認証のみ）。
	OAuth *OAuthConfig

	// Store はセッション・トークン等の保存先。
	// nil の場合、デフォルトの MemoryStore が使用される。
	Store Store

	// SessionMaxAge はブラウザセッションの最大有効期間。
	// デフォルト: 24時間。
	SessionMaxAge time.Duration

	// AccessTokenTTL は OAuth 2.1 Access Token の有効期間。
	// デフォルト: 1時間。
	AccessTokenTTL time.Duration

	// RefreshTokenTTL は OAuth 2.1 Refresh Token の有効期間。デフォルト: 30日。
	RefreshTokenTTL time.Duration

	// AuthCodeTTL は認可コードの有効期間。
	// デフォルト: 10分。
	AuthCodeTTL time.Duration

	// Logger は slog.Logger インスタンス。
	// nil の場合、slog.Default() を使用。
	Logger *slog.Logger

	// PathPrefix は OAuth 2.1 AS エンドポイントのパスプレフィックス。
	// デフォルト: "" （ルート直下）。
	// 例: "/auth" → /auth/authorize, /auth/token 等
	PathPrefix string
}

// OIDCProvider は1つの OIDC プロバイダーの設定を保持する。
type OIDCProvider struct {
	// Issuer は OIDC Issuer URL。
	// 例: "https://accounts.google.com"
	// 例: "https://login.microsoftonline.com/{tenant-id}/v2.0"
	Issuer string

	// ClientID は OAuth Client ID。
	ClientID string

	// ClientSecret は OAuth Client Secret。
	ClientSecret string

	// Scopes は要求するスコープ。
	// デフォルト: ["openid", "email", "profile"]
	Scopes []string

	// Name はプロバイダーの表示名（ログイン画面等で使用）。
	// 空の場合、Issuer から自動生成。
	Name string
}

// OAuthConfig は OAuth 2.1 Authorization Server の設定。
type OAuthConfig struct {
	// SigningKey は JWT 署名用の秘密鍵。
	// *ecdsa.PrivateKey（ES256）または *rsa.PrivateKey（RS256）。
	SigningKey crypto.Signer

	// SigningMethod は JWT 署名アルゴリズム。
	// デフォルト: SigningKey の型から自動判定（ECDSA → ES256, RSA → RS256）。
	SigningMethod jwt.SigningMethod

	// ClientID は OAuth 2.1 クライアント ID。
	// 静的クライアント設定用（動的クライアント登録は Phase 3 で追加）。
	// 空の場合、/authorize エンドポイントは任意の client_id を受け付ける。
	ClientID string

	// AllowedRedirectURIs は許可するリダイレクト URI のリスト。
	// /authorize エンドポイントで redirect_uri の検証に使用する。
	// 空の場合、localhost の URI のみ許可する（開発用）。
	AllowedRedirectURIs []string
}

// DefaultConfig は Config のデフォルト値を保持する。
var DefaultConfig = Config{
	SessionMaxAge:   24 * time.Hour,
	AccessTokenTTL:  1 * time.Hour,
	RefreshTokenTTL: 30 * 24 * time.Hour,
	AuthCodeTTL:     10 * time.Minute,
	PathPrefix:      "",
}

// DefaultScopes は OIDCProvider のデフォルトスコープ。
var DefaultScopes = []string{"openid", "email", "profile"}

// Validate は Config のバリデーションを行い、デフォルト値を適用する。
// 使用前に必ず呼び出すこと。
func (c *Config) Validate() error {
	// デフォルト値適用
	if c.SessionMaxAge == 0 {
		c.SessionMaxAge = DefaultConfig.SessionMaxAge
	}
	if c.AccessTokenTTL == 0 {
		c.AccessTokenTTL = DefaultConfig.AccessTokenTTL
	}
	if c.RefreshTokenTTL == 0 {
		c.RefreshTokenTTL = DefaultConfig.RefreshTokenTTL
	}
	if c.AuthCodeTTL == 0 {
		c.AuthCodeTTL = DefaultConfig.AuthCodeTTL
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}

	// Provider Scopes デフォルト適用（スライスコピーで mutation 防止）
	for i := range c.Providers {
		if len(c.Providers[i].Scopes) == 0 {
			c.Providers[i].Scopes = append([]string{}, DefaultScopes...)
		}
	}

	// バリデーション
	var errs []string

	if len(c.Providers) == 0 {
		errs = append(errs, "at least one provider is required")
	}
	for i, p := range c.Providers {
		if p.Issuer == "" {
			errs = append(errs, fmt.Sprintf("providers[%d]: issuer is required", i))
		}
		if p.ClientID == "" {
			errs = append(errs, fmt.Sprintf("providers[%d]: client_id is required", i))
		}
		if p.ClientSecret == "" {
			errs = append(errs, fmt.Sprintf("providers[%d]: client_secret is required", i))
		}
	}

	// ExternalURL（必須 + https:// チェック）
	if c.ExternalURL == "" {
		errs = append(errs, "external_url is required")
	} else if !strings.HasPrefix(c.ExternalURL, "https://") {
		if !isLocalhostURL(c.ExternalURL) {
			errs = append(errs, "external_url must start with https:// (except http://localhost)")
		}
	}

	// CookieSecret
	if len(c.CookieSecret) < 32 {
		errs = append(errs, "cookie_secret must be at least 32 bytes")
	}

	// OAuth
	if c.OAuth != nil && c.OAuth.SigningKey == nil {
		errs = append(errs, "oauth.signing_key is required when oauth is configured")
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation failed: %s", strings.Join(errs, "; "))
	}
	return nil
}

// isLocalhostURL は URL が http://localhost へのアクセスかどうかを判定する。
func isLocalhostURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
