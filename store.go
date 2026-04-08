package idproxy

import (
	"context"
	"time"
)

// Store はセッション、認可コード、アクセストークンの永続化インターフェース。
type Store interface {
	// セッション操作
	SetSession(ctx context.Context, id string, session *Session, ttl time.Duration) error
	GetSession(ctx context.Context, id string) (*Session, error)
	DeleteSession(ctx context.Context, id string) error

	// 認可コード操作（OAuth 2.1 AS 用）
	SetAuthCode(ctx context.Context, code string, data *AuthCodeData, ttl time.Duration) error
	GetAuthCode(ctx context.Context, code string) (*AuthCodeData, error)
	DeleteAuthCode(ctx context.Context, code string) error

	// アクセストークン操作（リボケーション用）
	SetAccessToken(ctx context.Context, jti string, data *AccessTokenData, ttl time.Duration) error
	GetAccessToken(ctx context.Context, jti string) (*AccessTokenData, error)
	DeleteAccessToken(ctx context.Context, jti string) error

	// クリーンアップ
	Cleanup(ctx context.Context) error
	Close() error
}

// Session はブラウザセッションのデータを保持する。
type Session struct {
	// ID はセッションの一意識別子（UUID v4）。
	ID string

	// User は認証済みユーザー情報。
	User *User

	// ProviderIssuer は認証に使用した IdP の Issuer URL。
	ProviderIssuer string

	// IDToken は IdP から取得した生の ID Token。
	// セッション復元時の検証やクレーム参照に使用。
	IDToken string

	// CreatedAt はセッション作成日時。
	CreatedAt time.Time

	// ExpiresAt はセッション有効期限。
	ExpiresAt time.Time
}

// AuthCodeData は OAuth 2.1 認可コードに紐づくデータを保持する。
type AuthCodeData struct {
	// Code は認可コード文字列（暗号論的乱数、32バイト hex）。
	Code string

	// ClientID は認可リクエストを送った OAuth クライアントの ID。
	ClientID string

	// RedirectURI は認可リクエストで指定されたリダイレクト URI。
	RedirectURI string

	// CodeChallenge は PKCE のコードチャレンジ（S256）。
	CodeChallenge string

	// CodeChallengeMethod は "S256" 固定。
	CodeChallengeMethod string

	// Scopes は認可されたスコープ。
	Scopes []string

	// User は認証済みユーザー情報。
	User *User

	// CreatedAt は認可コード発行日時。
	CreatedAt time.Time

	// ExpiresAt は認可コード有効期限（デフォルト10分）。
	ExpiresAt time.Time

	// Used は認可コードが既に使用済みかどうか。
	// OAuth 2.1 では認可コードは1回のみ使用可能。
	Used bool
}

// AccessTokenData はアクセストークンのメタデータを保持する。
// トークン自体は JWT として自己完結するが、
// リボケーション用に Store にも記録する。
type AccessTokenData struct {
	// JTI は JWT の一意識別子。
	JTI string

	// Subject はユーザーの OIDC sub クレーム。
	Subject string

	// Email はユーザーのメールアドレス。
	Email string

	// ClientID はトークンを発行した OAuth クライアントの ID。
	ClientID string

	// Scopes は付与されたスコープ。
	Scopes []string

	// IssuedAt はトークン発行日時。
	IssuedAt time.Time

	// ExpiresAt はトークン有効期限。
	ExpiresAt time.Time

	// Revoked はトークンがリボケーション済みかどうか。
	Revoked bool
}
