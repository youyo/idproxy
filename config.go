package idproxy

import (
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/text/unicode/norm"
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

	// DefaultPostLoginPath は認証完了後のデフォルトリダイレクト先。
	// 空文字列なら "/" を使用（現状互換）。
	// `LoginHandler` の `redirect_to` クエリが未指定の場合に使用される。
	// 先頭が "/" で始まる相対パスである必要があり、"//" で始まる
	// protocol-relative URL は禁止（Validate でエラー）。
	DefaultPostLoginPath string

	// OnAuthenticated は認証完了時（CallbackHandler 内の session 発行直後）に
	// 呼ばれるフック。
	//
	// 戻り値の解釈（4 状態）:
	//   - handled=true, redirectTo=""    : フック側で ResponseWriter に応答済み。
	//                                       BrowserAuth はリダイレクトしない。
	//   - handled=true, redirectTo!=""   : フック側で応答済みと解釈し、redirectTo
	//                                       は無視される（godoc 上の契約）。
	//   - handled=false, redirectTo!=""  : PostLoginRedirectValidator を通してから
	//                                       redirectTo へ 302。Validator が nil なら
	//                                       直接 302、Validator がエラーを返すなら 500。
	//   - handled=false, redirectTo==""  : 現状通り state に保存された RedirectURI へ 302。
	//
	// 呼び出し前後で `r.Context().Err() != nil` を検出した場合、BrowserAuth は
	// それ以降 ResponseWriter に何も書かずハンドラーを終了する（client cancellation 伝播）。
	//
	// フックは認証完了に同期で呼ばれるため、長い処理は呼び出し側で goroutine 化すること。
	// フック内で panic が発生した場合、BrowserAuth は recover して 500 を返す
	// （`http.ErrAbortHandler` だけは再 panic）。
	OnAuthenticated func(w http.ResponseWriter, r *http.Request, user *User) (redirectTo string, handled bool)

	// PostLoginRedirectValidator は post-login redirect 先の安全性を検証する関数。
	//
	// 適用される箇所:
	//   - `LoginHandler` の `redirect_to` クエリ
	//   - `SelectionHandler` の `redirect_to` クエリ
	//   - `Auth.Wrap` の未認証ブラウザリクエストで生成される `redirect_to`
	//   - `OAuthServer.redirectToLogin` の `redirect_to`
	//   - `OnAuthenticated` フック戻り値の `redirectTo`
	//
	// nil なら検査しない（v0.4.2 までの動作互換、純粋 API 追加）。
	// `StrictPostLoginRedirectValidator(cfg.ExternalURL)` または
	// `(*Config).UseStrictPostLoginRedirectValidator()` を呼ぶことで opt-in できる。
	//
	// Validator が non-nil でエラーを返した場合、入力起因のため 400 を返す（500 ではない）。
	// Validator 内 panic は BrowserAuth 側で recover して 500 を返す。
	PostLoginRedirectValidator func(redirectTo string) error

	// StoreIDToken は、セッションに保存済みの生の ID Token を
	// UserFromContext(ctx).IDToken 経由でハンドラーに公開するかどうかを指定する。
	//
	// デフォルト: false（既存動作を維持）。
	//
	// 注意: ID Token はこの設定に関わらず常にセッションストアに保存される。
	// この設定は「保存するかどうか」ではなく「コンテキストへ露出するかどうか」を制御する。
	//
	// true にすると、OIDC コールバック（ブラウザ認証フロー）経由でログインしたとき、
	// UserFromContext(ctx).IDToken に IdP が発行した ID Token 文字列がセットされる。
	// Bearer Token フロー（セッションなし）では常に空文字列となる。
	//
	// 主な用途: AWS STS AssumeRoleWithWebIdentity など、
	// IdP が発行したトークンをそのままダウンストリームサービスに渡す必要がある場合。
	//
	// 注意:
	//   - ストアの暗号化が有効であることを確認すること。
	//   - ID Token の有効期限（exp クレーム）はセッション有効期限より短い場合がある（多くの
	//     IdP では約 1 時間）。IDToken を使用する際は呼び出し側で exp を確認すること。
	//     期限切れでも UserFromContext(ctx).IDToken は空でない文字列を返し続ける。
	StoreIDToken bool
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

	// DefaultPostLoginPath（空文字列は許容、設定値は先頭スラッシュ必須・"//" 禁止）
	if c.DefaultPostLoginPath != "" {
		if !strings.HasPrefix(c.DefaultPostLoginPath, "/") {
			errs = append(errs, "default_post_login_path must start with '/'")
		} else if strings.HasPrefix(c.DefaultPostLoginPath, "//") {
			errs = append(errs, "default_post_login_path must not start with '//' (protocol-relative URL not allowed)")
		}
		// PostLoginRedirectValidator が設定されているなら、DefaultPostLoginPath にも同じ Validator を適用する
		if c.PostLoginRedirectValidator != nil {
			if vErr := c.PostLoginRedirectValidator(c.DefaultPostLoginPath); vErr != nil {
				errs = append(errs, fmt.Sprintf("default_post_login_path rejected by validator: %v", vErr))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation failed: %s", strings.Join(errs, "; "))
	}
	return nil
}

// ErrUnsafePostLoginRedirect は PostLoginRedirectValidator がリダイレクト先を
// 拒否した時に返される sentinel エラー。利用側で errors.Is で判定できる。
var ErrUnsafePostLoginRedirect = errors.New("idproxy: unsafe post-login redirect")

// StrictPostLoginRedirectValidator は post-login redirect 先を厳格に検査する
// `func(string) error` を返す。利用側が opt-in で安全側に切り替えるための helper。
//
// externalURL は Config.ExternalURL と同一の値を渡す（同一 origin の絶対 URL
// 許可判定に使用する）。空文字列を渡した場合は「相対パスのみ許可」モードになる。
//
// 許可条件（多段検査、順番に評価する）:
//  1. `strings.TrimSpace` 後の入力に `unicode.IsControl` を含むなら reject
//  2. backslash や HTML 構造文字 `\<>"'` を含むなら reject
//  3. NFKC 正規化後と元の入力で差分があるなら reject（同形異字攻撃排除）
//  4. `url.Parse` で scheme/host を取得し、以下のいずれかに合致するなら通過:
//     - 相対パス: scheme="" かつ host="" かつ "/" で始まり "//" で始まらない
//     - 同一 origin の絶対 URL: scheme="https" かつ host==externalURL の host
//  5. それ以外は reject（`javascript:`/`data:`/`vbscript:`/`file:`/protocol-relative も拒否）
//
// 拒否時は `ErrUnsafePostLoginRedirect` を wrap した error を返す。
func StrictPostLoginRedirectValidator(externalURL string) func(string) error {
	var externalHost string
	if externalURL != "" {
		if u, err := url.Parse(externalURL); err == nil {
			externalHost = u.Host
		}
	}

	return func(redirectTo string) error {
		// 空文字列は呼び出し側がデフォルトを当てるため許容（DefaultPostLoginPath 空 + クエリ空時の経路）。
		if redirectTo == "" {
			return nil
		}

		trimmed := strings.TrimSpace(redirectTo)
		if trimmed != redirectTo {
			return fmt.Errorf("%w: leading/trailing whitespace", ErrUnsafePostLoginRedirect)
		}

		// 制御文字・format 文字（ゼロ幅スペース U+200B 等の Cf カテゴリも含む）を排除
		for _, r := range trimmed {
			if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
				return fmt.Errorf("%w: contains control or format character", ErrUnsafePostLoginRedirect)
			}
		}

		// 構造文字（backslash で `\evil.com`、HTML/quote 系も）排除
		if strings.ContainsAny(trimmed, "\\<>\"'") {
			return fmt.Errorf("%w: contains unsafe character", ErrUnsafePostLoginRedirect)
		}

		// NFKC 正規化前後で差分があれば、同形異字攻撃を疑い reject
		if norm.NFKC.String(trimmed) != trimmed {
			return fmt.Errorf("%w: not NFKC-normalized", ErrUnsafePostLoginRedirect)
		}

		u, err := url.Parse(trimmed)
		if err != nil {
			return fmt.Errorf("%w: parse error: %v", ErrUnsafePostLoginRedirect, err)
		}

		// 相対パス（scheme + host とも空）の場合は "/" 始まりかつ "//" 始まりでないこと
		if u.Scheme == "" && u.Host == "" {
			if !strings.HasPrefix(trimmed, "/") {
				return fmt.Errorf("%w: relative path must start with '/'", ErrUnsafePostLoginRedirect)
			}
			if strings.HasPrefix(trimmed, "//") {
				return fmt.Errorf("%w: protocol-relative URL not allowed", ErrUnsafePostLoginRedirect)
			}
			return nil
		}

		// 絶対 URL：https かつ ExternalURL と同一 host のみ許可
		if u.Scheme == "https" && externalHost != "" && u.Host == externalHost {
			return nil
		}

		return fmt.Errorf("%w: scheme=%q host=%q not allowed", ErrUnsafePostLoginRedirect, u.Scheme, u.Host)
	}
}

// UseStrictPostLoginRedirectValidator は Config.PostLoginRedirectValidator に
// `StrictPostLoginRedirectValidator(c.ExternalURL)` を設定するヘルパー。
//
// 呼び出すと Strict Validator が opt-in され、相対パスおよび同一 origin の
// 絶対 URL のみが許可される。`Config.ExternalURL` の渡し忘れを防ぐため、
// 利用側はこのメソッド経由でセットすることを推奨する。
func (c *Config) UseStrictPostLoginRedirectValidator() {
	c.PostLoginRedirectValidator = StrictPostLoginRedirectValidator(c.ExternalURL)
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
