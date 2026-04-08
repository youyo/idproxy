package idproxy

import (
	"crypto"
	"log/slog"
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
}

// DefaultConfig は Config のデフォルト値を保持する。
var DefaultConfig = Config{
	SessionMaxAge:  24 * time.Hour,
	AccessTokenTTL: 1 * time.Hour,
	AuthCodeTTL:    10 * time.Minute,
	PathPrefix:     "",
}

// DefaultScopes は OIDCProvider のデフォルトスコープ。
var DefaultScopes = []string{"openid", "email", "profile"}
