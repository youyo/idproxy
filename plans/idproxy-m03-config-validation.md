# M03: Config バリデーション 詳細計画

## 概要

Config.Validate() メソッドを実装し、設定値のバリデーションとデフォルト値の適用を行う。

## スコープ

### 実装対象
1. `Config.Validate() error` メソッド
2. デフォルト値適用ロジック（SessionMaxAge, AccessTokenTTL, AuthCodeTTL, PathPrefix）
3. OIDCProvider の Scopes デフォルト設定（未設定時に DefaultScopes を適用）
4. Logger のデフォルト設定（nil の場合 slog.Default()）

### バリデーションルール（スペック Section 10 準拠）
1. **Providers**: 1つ以上必須 → `len(c.Providers) == 0` でエラー
2. **ExternalURL**: `https://` で始まること。例外: `http://localhost` パターン（ローカル開発用）
3. **CookieSecret**: 32バイト以上 → `len(c.CookieSecret) < 32` でエラー
4. **OAuth.SigningKey**: OAuth 設定時（`c.OAuth != nil`）は SigningKey 必須 → `c.OAuth.SigningKey == nil` でエラー
5. **OIDCProvider 個別**: 各プロバイダーの Issuer, ClientID, ClientSecret が空でないこと

### Design Decision
- `AllowedDomains` と `AllowedEmails` が両方未設定の場合、全員許可として実装
  → バリデーションエラーにしない
  → 注意: スペック Section 14 (Open Questions) で未確定。変更時は Validate() のみ修正で対応可能

## TDD 設計（Red → Green → Refactor）

### Step 1: Red Phase — テスト作成

`config_test.go` に以下のテストを追加:

#### テストケース一覧

```go
// 1. 正常系: 最小限の有効な Config
func TestValidate_MinimalValid(t *testing.T)
// Providers 1つ、ExternalURL https、CookieSecret 32バイト → nil

// 2. 正常系: OAuth 有効な Config
func TestValidate_WithOAuth(t *testing.T)
// OAuth != nil、SigningKey 設定済み → nil

// 3. 異常系: Providers 空
func TestValidate_NoProviders(t *testing.T)
// Providers: nil → error 含む "at least one provider"

// 4. 異常系: ExternalURL が https でない
func TestValidate_ExternalURL_NotHTTPS(t *testing.T)
// ExternalURL: "http://example.com" → error

// 5. 正常系: ExternalURL が http://localhost（例外）
func TestValidate_ExternalURL_Localhost(t *testing.T)
// ExternalURL: "http://localhost:8080" → nil

// 6. 異常系: CookieSecret が短い
func TestValidate_CookieSecret_TooShort(t *testing.T)
// CookieSecret: 31バイト → error

// 7. 異常系: CookieSecret が空
func TestValidate_CookieSecret_Empty(t *testing.T)
// CookieSecret: nil → error

// 8. 異常系: OAuth 設定あり、SigningKey なし
func TestValidate_OAuth_NoSigningKey(t *testing.T)
// OAuth: &OAuthConfig{} → error

// 9. 異常系: Provider の Issuer 空
func TestValidate_Provider_EmptyIssuer(t *testing.T)

// 10. 異常系: Provider の ClientID 空
func TestValidate_Provider_EmptyClientID(t *testing.T)

// 11. 異常系: Provider の ClientSecret 空
func TestValidate_Provider_EmptyClientSecret(t *testing.T)

// 12. デフォルト値適用: SessionMaxAge
func TestValidate_DefaultSessionMaxAge(t *testing.T)
// SessionMaxAge: 0 → Validate後 24h

// 13. デフォルト値適用: AccessTokenTTL
func TestValidate_DefaultAccessTokenTTL(t *testing.T)

// 14. デフォルト値適用: AuthCodeTTL
func TestValidate_DefaultAuthCodeTTL(t *testing.T)

// 15. デフォルト値適用: Scopes
func TestValidate_DefaultScopes(t *testing.T)
// Provider.Scopes: nil → DefaultScopes が適用される

// 16. デフォルト値適用: Logger
func TestValidate_DefaultLogger(t *testing.T)
// Logger: nil → slog.Default()

// 17. 正常系: AllowedDomains/Emails 未設定（全員許可）
func TestValidate_NoAllowedDomainsOrEmails(t *testing.T)
// AllowedDomains: nil, AllowedEmails: nil → nil（エラーにならない）

// 18. 正常系: ExternalURL http://127.0.0.1 も localhost 例外
func TestValidate_ExternalURL_127001(t *testing.T)

// 19. 複数エラーの集約テスト
func TestValidate_MultipleErrors(t *testing.T)
// Providers 空 + CookieSecret 短い → 両方のエラーメッセージを含む

// 20. 異常系: ExternalURL 空文字
func TestValidate_ExternalURL_Empty(t *testing.T)
// ExternalURL: "" → error (必須フィールド)
```

#### テストヘルパー

```go
// validConfig はテスト用の最小限有効な Config を返す。
func validConfig() Config {
    return Config{
        Providers: []OIDCProvider{{
            Issuer:       "https://accounts.google.com",
            ClientID:     "test-client-id",
            ClientSecret: "test-client-secret",
        }},
        ExternalURL:  "https://auth.example.com",
        CookieSecret: make([]byte, 32),
    }
}
```

#### crypto.Signer テスト用生成

OAuth 有効テスト（TestValidate_WithOAuth）では以下で ECDSA 鍵を生成:
```go
key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// import: "crypto/ecdsa", "crypto/elliptic", "crypto/rand"
```

### Step 2: Green Phase — 最小実装

`config.go` に `Validate()` メソッドを追加:

```go
func (c *Config) Validate() error {
    var errs []string

    // デフォルト値適用
    if c.SessionMaxAge == 0 {
        c.SessionMaxAge = DefaultConfig.SessionMaxAge
    }
    if c.AccessTokenTTL == 0 {
        c.AccessTokenTTL = DefaultConfig.AccessTokenTTL
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
```

### Step 3: Refactor Phase

- エラー集約を `errors.Join` パターンに変更するか検討（Go 1.20+）
- `isLocalhostURL` のテストを独立させるか検討
- テストを `t.Run` サブテスト形式に統合するか検討

## 実装ステップ（順序）

1. `config_test.go` にテストヘルパー `validConfig()` を追加
2. `config_test.go` にバリデーションテスト（20ケース）を追加
3. `go test ./...` で全テスト失敗を確認（Red）
4. `config.go` に `Validate()` メソッドと `isLocalhostURL()` を実装
5. `go test ./...` で全テスト成功を確認（Green）
6. リファクタリング（必要に応じて）
7. `go test ./...` で再確認
8. `git add && git commit`

## 追加 import

`config.go` に以下の import が必要:
- `fmt`
- `strings`
- `net/url`

## リスク評価

| リスク | 影響度 | 対策 |
|--------|--------|------|
| ExternalURL の localhost 判定が不十分 | 中 | `net/url.Parse` + Hostname() で正確に判定。`::1` も対応 |
| デフォルト値適用が Validate 内で行われるため、呼び忘れリスク | 中 | godoc に「使用前に必ず Validate() を呼ぶこと」を明記。将来的に New() コンストラクタで自動呼び出し |
| errors.Join vs 文字列結合の選択 | 低 | 初期は strings.Join で簡潔に。将来 sentinel error が必要になったら errors.Join に移行 |
| Validate() がポインタレシーバ（*Config）であること | 低 | デフォルト値適用で構造体を変更するため、ポインタレシーバが必須 |
| PathPrefix のバリデーション未実装 | 低 | スペックにバリデーションルール記載なし。将来的に "/" 始まりチェック等を追加可能 |

## ファイル変更一覧

| ファイル | 変更内容 |
|----------|----------|
| `config.go` | `Validate()` メソッド、`isLocalhostURL()` 関数追加、import 追加 |
| `config_test.go` | `validConfig()` ヘルパー、20テストケース追加 |

## 前提条件

- M02 で Config, OIDCProvider, OAuthConfig, DefaultConfig, DefaultScopes が定義済み
- `go test ./...` が現在 green であること
