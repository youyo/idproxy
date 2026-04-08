# Product Spec: idproxy

## Meta

| 項目 | 値 |
|------|---|
| バージョン | 1.0.0 |
| 作成日 | 2026-04-08 |
| 最終更新 | 2026-04-08 15:00 |
| ステータス | Draft |
| リポジトリ | github.com/youyo/idproxy |
| 言語 | Go 1.26 |
| ライセンス | MIT or Apache 2.0（TBD） |

---

## 1. Overview

### 解決する課題

Remote MCP server（Model Context Protocol）を外部公開する際に、MCP プロトコル自体には認証機構が存在しない。そのため HTTP レイヤーで認証を挟む必要があるが、既存の OSS（Pomerium、OAuth2 Proxy 等）は以下の問題を抱える:

- **Pomerium**: Envoy ベースの Zero-Trust フレームワーク全体を持ち込むことになりオーバーキル。OSS 版は File Watch の不安定報告あり（Issue #1818）、動的ルート追加は Enterprise 限定
- **OAuth2 Proxy**: SSE パススルーに要設定、MCP OAuth 2.1 Authorization Server 機能なし
- **Authelia**: 単体では SSE 対応に上流リバースプロキシ（Nginx/Caddy）の追加設定が必要
- **自前 nginx 設定**: MCP OAuth 2.1 対応が不可能、構成が複雑化

いずれも「OIDC 認証 + SSE 透過 + MCP OAuth 2.1 AS」を1つのコンポーネントで提供できない。

### ターゲットユーザー

| セグメント | 説明 | 利用形態 |
|-----------|------|---------|
| 自社チーム（heptagon） | 社内 Remote MCP server の認証基盤として導入 | スタンドアロンプロキシ + ライブラリ組み込み |
| Go 開発者（OSS） | Go で HTTP サーバーや MCP サーバーを書く開発者 | `go get` でライブラリとして組み込み |
| DevOps / インフラエンジニア | 既存の MCP server に認証レイヤーを追加したい | スタンドアロンプロキシとしてデプロイ |

### 既存代替手段の課題

| 代替手段 | EntraID | Google | MCP SSE 対応 | MCP OAuth 2.1 AS | 軽量度 |
|---------|---------|--------|-------------|-----------------|--------|
| Pomerium | ○ | ○ | ○ | × | 中（Envoy 依存） |
| OAuth2 Proxy | ○ | ○ | △ 要設定 | × | 小 |
| Authelia | ○ | ○ | △ 要設定 | × | 小 |
| nginx + OIDC module | ○ | ○ | △ 要設定 | × | 中（構成複雑） |
| **idproxy（本プロジェクト）** | **○** | **○** | **○ ネイティブ** | **○** | **最小** |

差別化ポイント: **OIDC 認証 + MCP OAuth 2.1 AS + SSE 透過を単一の Go バイナリ / ライブラリで提供**する唯一のソリューション。

---

## 2. Goals / Non-goals

### 3ヶ月後のゴール

1. heptagon 社内の全 Remote MCP server が idproxy 経由で認証付きで公開されている
2. GitHub で OSS として公開済み、外部ユーザーも使い始めている
3. Claude Desktop / Claude Cowork から OAuth 2.1 で認証付き MCP 接続ができる

### 成功指標（KPI）

| 指標 | 現状 | 目標値 |
|------|------|--------|
| 社内 MCP server の認証カバー率 | 0% | 100% |
| GitHub Stars | 0 | 50+ |
| 外部からの Issue / PR | 0 | 1+ |
| Claude Cowork からの OAuth 2.1 接続成功率 | N/A | 100%（手動テスト） |

### 意図的にスコープ外とするもの

| 機能 | 理由 |
|------|------|
| RBAC / ツール単位アクセス制御 | MVP では「認証されたユーザー全員が全ツールを使える」で十分。ツール単位の制御は MCP 特化ゲートウェイの成熟を待つ |
| レートリミット | 上流のロードバランサーや API Gateway で対応可能。認証レイヤーの責務ではない |
| 監査ログ / アクセスログ | Go 標準の `slog` で最小限のログは出力するが、構造化された監査ログ機能は Phase 2 |
| WebSocket 対応 | MCP の Streamable HTTP transport は SSE ベース。WebSocket は MCP spec で非推奨方向 |
| Docker イメージ | バイナリ配布で十分。必要になった時点で追加 |
| Kubernetes CRD / Operator | スタンドアロンバイナリとして Deployment にデプロイすればよい |
| 複数 upstream ルーティング | 1 インスタンスにつき 1 upstream。複数の MCP server には複数インスタンスをデプロイ |

---

## 3. Scope

### MVP（フェーズ1）に含むもの

1. **OIDC 認証ミドルウェア**
   - 複数 OIDC プロバイダーの同時サポート（EntraID + Google）
   - OIDC Discovery による自動設定
   - ID Token 検証（署名、issuer、audience、expiry）
   - ドメイン + メールリストによる認可ポリシー

2. **MCP OAuth 2.1 Authorization Server**
   - RFC 8414 Authorization Server Metadata エンドポイント
   - Authorization Code Flow with PKCE（RFC 7636）
   - Access Token 発行（JWT 署名）
   - Bearer Token 検証
   - 上流 IdP への認証委譲

3. **ブラウザベース認証**
   - OIDC Authorization Code Flow
   - Cookie + encrypted JWT セッション管理
   - セッションの有効期限管理

4. **SSE / Streamable HTTP 透過**
   - `httputil.ReverseProxy` + `FlushInterval: -1`
   - 認証後のストリーミングパススルー

5. **http.Handler ミドルウェア**
   - `Wrap(next http.Handler) http.Handler` パターン
   - 任意の Go HTTP サーバーに組み込み可能

6. **スタンドアロンプロキシバイナリ**
   - 環境変数のみで設定
   - 単一バイナリでデプロイ可能

7. **Store インターフェース**
   - セッション、認可コード、トークンの保存先を抽象化
   - デフォルト: インメモリ実装

### フェーズ2以降の展望

| フェーズ | 機能 | 優先度 |
|---------|------|--------|
| Phase 2 | 監査ログ（構造化ログ出力） | 高 |
| Phase 2 | Redis Store 実装 | 高 |
| Phase 2 | Docker イメージ配布 | 中 |
| Phase 2 | Prometheus メトリクス | 中 |
| Phase 3 | RBAC / グループベースアクセス制御 | 中 |
| Phase 3 | トークンリフレッシュ | 中 |
| Phase 3 | SAML 対応 | 低 |
| Future | WebSocket 対応 | 低 |
| Future | Kubernetes CRD | 低 |

---

## 4. Distribution & Execution Model

### 配布形態

| 形態 | 対象 | インストール方法 |
|------|------|----------------|
| Go ライブラリ | Go 開発者 | `go get github.com/youyo/idproxy` |
| スタンドアロンバイナリ | DevOps / インフラ | GitHub Releases からダウンロード |

### メイン実行ファイルと起動方法

#### ライブラリとして組み込み

```go
package main

import (
    "net/http"
    "github.com/youyo/idproxy"
)

func main() {
    auth := idproxy.New(idproxy.Config{
        Providers: []idproxy.OIDCProvider{
            {
                Issuer:       "https://accounts.google.com",
                ClientID:     "xxx.apps.googleusercontent.com",
                ClientSecret: "xxx",
            },
            {
                Issuer:       "https://login.microsoftonline.com/{tenant}/v2.0",
                ClientID:     "yyy",
                ClientSecret: "yyy",
            },
        },
        AllowedDomains: []string{"heptagon.co.jp"},
        AllowedEmails:  []string{"partner@example.com"},
        ExternalURL:    "https://mcp-auth.example.com",
        CookieSecret:   []byte("32-byte-random-key-here-12345678"),
        OAuth: &idproxy.OAuthConfig{
            SigningKey: privateKey, // *ecdsa.PrivateKey or *rsa.PrivateKey
        },
    })

    mux := http.NewServeMux()
    mux.Handle("/mcp", mcpHandler) // 任意の MCP サーバー実装

    http.ListenAndServe(":8080", auth.Wrap(mux))
}
```

#### mcp-go との統合例

```go
package main

import (
    "net/http"
    "github.com/mark3labs/mcp-go/server"
    "github.com/youyo/idproxy"
)

func main() {
    // MCP サーバーを構築
    mcpServer := server.NewMCPServer("my-server", "1.0.0")
    // ... ツール・リソース登録 ...

    httpServer := server.NewStreamableHTTPServer(mcpServer)

    // idproxy で認証を被せる
    auth := idproxy.New(idproxy.Config{
        Providers: []idproxy.OIDCProvider{
            {
                Issuer:       "https://accounts.google.com",
                ClientID:     "xxx",
                ClientSecret: "xxx",
            },
        },
        AllowedDomains: []string{"heptagon.co.jp"},
        ExternalURL:    "https://mcp.example.com",
        CookieSecret:   []byte("32-byte-random-key-here-12345678"),
        OAuth: &idproxy.OAuthConfig{
            SigningKey: privateKey,
        },
    })

    http.ListenAndServe(":8080", auth.Wrap(httpServer))
}
```

#### スタンドアロンプロキシとして起動

```bash
export OIDC_ISSUER="https://accounts.google.com,https://login.microsoftonline.com/{tenant}/v2.0"
export OIDC_CLIENT_ID="google-client-id,azure-client-id"
export OIDC_CLIENT_SECRET="google-secret,azure-secret"
export ALLOWED_DOMAINS="heptagon.co.jp"
export ALLOWED_EMAILS="partner@example.com"
export UPSTREAM="http://localhost:3000"
export LISTEN_ADDR=":8080"
export COOKIE_SECRET="$(openssl rand -hex 16)"
export JWT_SIGNING_KEY_FILE="/path/to/private-key.pem"
export EXTERNAL_URL="https://mcp-auth.example.com"

idproxy
```

### インストール方法

```bash
# Go ライブラリとして
go get github.com/youyo/idproxy

# バイナリ（GitHub Releases）
# Linux
curl -sL https://github.com/youyo/idproxy/releases/latest/download/idproxy_linux_amd64.tar.gz | tar xz
sudo mv idproxy /usr/local/bin/

# macOS
curl -sL https://github.com/youyo/idproxy/releases/latest/download/idproxy_darwin_arm64.tar.gz | tar xz
sudo mv idproxy /usr/local/bin/

# Go install
go install github.com/youyo/idproxy/cmd/idproxy@latest
```

### バックグラウンドプロセス

なし。単一プロセスで動作する。セッションの期限切れクリーンアップは goroutine で実行する（別プロセスではない）。

---

## 5. Architecture

### 主要コンポーネント

```
┌─────────────────────────────────────────────────────┐
│                    idproxy                           │
│                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │  AuthHandler  │  │  OAuthServer │  │  Proxy     │ │
│  │              │  │              │  │            │ │
│  │ - OIDC検証    │  │ - /authorize │  │ - Reverse  │ │
│  │ - Cookie管理  │  │ - /token     │  │   Proxy    │ │
│  │ - Bearer検証  │  │ - /callback  │  │ - SSE透過  │ │
│  │ - 認可判定    │  │ - /.well-known│  │            │ │
│  └──────┬───────┘  └──────┬───────┘  └─────┬──────┘ │
│         │                 │                │        │
│  ┌──────┴─────────────────┴────────────────┴──────┐ │
│  │                  Store Interface                │ │
│  │  - Sessions  - AuthCodes  - Tokens             │ │
│  └────────────────────┬───────────────────────────┘ │
│                       │                              │
│  ┌────────────────────┴───────────────────────────┐ │
│  │           MemoryStore (default)                 │ │
│  │           RedisStore (Phase 2)                  │ │
│  └────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

| コンポーネント | 責務 | 実装ファイル |
|--------------|------|------------|
| **Auth** | トップレベル構造体。`Wrap()` メソッドでミドルウェアを提供 | `auth.go` |
| **AuthHandler** | リクエストごとの認証判定。Cookie or Bearer token を検証し、認可ポリシーを適用 | `auth.go` |
| **OAuthServer** | OAuth 2.1 Authorization Server エンドポイント群。MCP クライアント向け | `oauth2.go` |
| **SessionManager** | Cookie ベースのセッション管理。暗号化 JWT の発行・検証 | `session.go` |
| **Store** | セッション、認可コード、トークンの永続化インターフェース | `store.go` |
| **MemoryStore** | Store のインメモリ実装（デフォルト） | `store/memory.go` |
| **Config** | 設定構造体。バリデーション付き | `config.go` |
| **Proxy** | `httputil.ReverseProxy` ラッパー。SSE 透過設定済み（スタンドアロンモードのみ） | `cmd/idproxy/main.go` |

### プロセスモデル

**単一バイナリ / 単一プロセス**。全てのコンポーネントが同一プロセス内で動作する。

- HTTP サーバー: `net/http` 標準
- セッションクリーンアップ: バックグラウンド goroutine（`time.Ticker`）
- OIDC Discovery キャッシュ: `go-oidc` ライブラリ内蔵のキャッシュ

### アーキテクチャ決定記録（ADR）

| # | 決定 | 理由 | 却下した選択肢 |
|---|------|------|-------------|
| 1 | http.Handler ミドルウェアパターンを採用 | Go の標準的なパターンで、任意の HTTP サーバーに組み込み可能。mcp-go の StreamableHTTPServer が http.Handler を実装しているため直接互換 | フレームワーク固有のミドルウェア（gin, echo 等）、gRPC interceptor |
| 2 | Cookie + encrypted JWT でブラウザセッション管理 | ステートレス（サーバー側にセッション状態不要）、gorilla/securecookie で実績あり | サーバーサイドセッション（Redis 必須になる）、JWE |
| 3 | Store インターフェースで永続化を抽象化 | 利用者の環境に応じて差し替え可能。MVP はインメモリで外部依存ゼロ | Redis 固定（外部依存が増える）、ファイルベース（スケールしない） |
| 4 | 環境変数のみで設定（スタンドアロン） | 12-factor app 準拠。Docker / K8s との親和性が最も高い | YAML 設定ファイル（ファイル管理が必要）、CLI フラグ（長くなる） |
| 5 | 複数 IdP を同時サポート | 社内環境では EntraID と Google の両方が使われるケースが一般的。差別化ポイント | 単一 IdP のみ（Phase 2 で追加する案は、社内利用で即座に困る） |
| 6 | coreos/go-oidc を OIDC 検証に使用 | OIDC Discovery、ID Token 検証、JWK キャッシュを全てカバー。Go OIDC ライブラリのデファクトスタンダード | 自前実装（リスクが高すぎる）、zitadel/oidc（サーバーサイド寄り） |
| 7 | golang-jwt/jwt で OAuth 2.1 トークン発行 | Go JWT ライブラリのデファクトスタンダード。ES256, RS256 両方サポート | lestrrat-go/jwx（高機能だが学習コスト高い）、自前署名 |
| 8 | PKCE は S256 のみサポート | OAuth 2.1 では S256 が必須（plain は禁止）。実装がシンプル | plain サポート（セキュリティリスク、OAuth 2.1 非準拠） |

---

## 6. Interfaces & Contracts

### ライブラリ API

#### トップレベル構造体と関数

```go
package idproxy

// New は Auth インスタンスを生成する。
// Config のバリデーションに失敗した場合は error を返す。
func New(cfg Config) (*Auth, error)

// Auth は OIDC 認証ミドルウェアのトップレベル構造体。
type Auth struct {
    // 非公開フィールド
}

// Wrap は http.Handler をラップして認証を追加する。
// 認証済みリクエストのみ next に転送される。
// OAuth 2.1 AS エンドポイント（/authorize, /token, /callback, /.well-known/*）は
// 自動的にルーティングされ、next には転送されない。
func (a *Auth) Wrap(next http.Handler) http.Handler

// Handler は Auth 自体を http.Handler として返す（スタンドアロンモード用）。
// 内部で httputil.ReverseProxy を使用し、upstream にプロキシする。
func (a *Auth) Handler() http.Handler
```

#### Config 構造体

```go
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
```

#### Store インターフェース

```go
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
```

#### コンテキストから認証情報を取得

```go
// UserFromContext はリクエストコンテキストから認証済みユーザー情報を取得する。
// 認証されていない場合は nil を返す。
func UserFromContext(ctx context.Context) *User

// User は認証済みユーザーの情報を保持する。
type User struct {
    // Email はユーザーのメールアドレス。
    Email string

    // Name はユーザーの表示名。
    Name string

    // Subject は OIDC sub クレーム。
    Subject string

    // Issuer は認証に使用された IdP の Issuer URL。
    Issuer string

    // Claims は ID Token の全クレーム（map[string]interface{}）。
    Claims map[string]interface{}
}
```

### エラーハンドリングポリシー

| 状況 | HTTP ステータス | レスポンス |
|------|---------------|----------|
| 未認証（Cookie なし、Bearer なし） | 401 Unauthorized | ブラウザ: IdP へリダイレクト / MCP: `WWW-Authenticate` ヘッダー付き 401 |
| Cookie 期限切れ | 401 Unauthorized | IdP へ再リダイレクト |
| Bearer Token 無効 / 期限切れ | 401 Unauthorized | `{"error": "invalid_token"}` |
| ドメイン / メール不許可 | 403 Forbidden | `{"error": "access_denied", "error_description": "..."}` |
| OIDC Discovery 失敗 | 502 Bad Gateway | `{"error": "upstream_error"}` |
| IdP 認証エラー（コールバック） | 400 Bad Request | エラーページ表示 |
| PKCE 検証失敗 | 400 Bad Request | `{"error": "invalid_grant"}` |
| 認可コード不正 / 期限切れ | 400 Bad Request | `{"error": "invalid_grant"}` |
| Config バリデーション失敗 | N/A（起動時 panic） | エラーメッセージをログ出力 |

#### リクエスト判定ロジック（認証フロー選択）

```
リクエスト受信
├─ パスが OAuth 2.1 AS エンドポイント（/authorize, /token, /callback, /.well-known/*）？
│  └─ はい → OAuthServer が処理
├─ Authorization: Bearer ヘッダーあり？
│  └─ はい → Bearer Token 検証 → 有効なら next へ、無効なら 401
├─ 有効な Session Cookie あり？
│  └─ はい → セッション検証 → 有効なら next へ、期限切れなら IdP リダイレクト
└─ 何もなし
   ├─ Accept: text/html を含む（ブラウザ）？
   │  └─ はい → IdP へリダイレクト
   └─ いいえ（API クライアント）
      └─ 401 + WWW-Authenticate ヘッダー
```

---

## 7. Storage & Data Model

### Store インターフェース

前述の `Store` インターフェースを参照。以下はデータ構造の定義。

### セッションデータ構造

```go
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
```

### 認可コードデータ構造

```go
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
```

### アクセストークンデータ構造

```go
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
```

### MemoryStore の実装方針

- `sync.Map` または `sync.RWMutex` + `map[string]T` で実装
- TTL 管理: 各エントリに `ExpiresAt` を持たせ、`Get` 時に期限切れをチェック
- バックグラウンドクリーンアップ: `time.Ticker`（5分間隔）で期限切れエントリを削除
- `Close()` で Ticker を停止

---

## 8. Runtime Flows

### フロー1: ブラウザベース OIDC 認証

```
1. ブラウザが upstream リソースにアクセス
   GET https://mcp-auth.example.com/mcp
   Cookie: なし

2. idproxy が未認証を検出
   - Accept: text/html → ブラウザと判定
   - セッション Cookie なし

3. IdP 選択（複数プロバイダーの場合）
   - プロバイダーが1つ → 直接リダイレクト
   - プロバイダーが複数 → プロバイダー選択ページを表示
     （シンプルな HTML: "Sign in with Google" / "Sign in with Microsoft"）

4. OIDC Authorization Request を生成
   - state パラメータ: 暗号論的乱数（CSRF 防止）
   - nonce パラメータ: 暗号論的乱数（リプレイ防止）
   - redirect_uri: {EXTERNAL_URL}/callback
   - scope: openid email profile
   - Store に state → {nonce, provider_issuer, original_url} を保存

5. ブラウザを IdP にリダイレクト
   302 → https://accounts.google.com/o/oauth2/v2/auth?...

6. ユーザーが IdP で認証

7. IdP がコールバックにリダイレクト
   GET https://mcp-auth.example.com/callback?code=xxx&state=yyy

8. idproxy がコールバックを処理
   a. state を Store から取得・検証
   b. 認可コードを IdP の token エンドポイントで交換 → ID Token + Access Token
   c. ID Token を go-oidc で検証（署名、issuer、audience、nonce、expiry）
   d. email クレームを取得
   e. AllowedDomains / AllowedEmails で認可判定
   f. 認可 OK → Session を生成、Store に保存
   g. 暗号化 Cookie を Set-Cookie ヘッダーで発行
   h. 元の URL にリダイレクト

9. ブラウザが元のリソースに再アクセス
   GET https://mcp-auth.example.com/mcp
   Cookie: _idproxy_session=<encrypted-jwt>

10. idproxy がセッション Cookie を検証
    a. Cookie を復号（gorilla/securecookie）
    b. JWT クレームを検証（expiry）
    c. Store からセッションを取得（存在確認）
    d. 認証済みユーザー情報をコンテキストに注入
    e. next.ServeHTTP(w, r) を呼び出し → upstream へ
```

### フロー2: MCP OAuth 2.1 認証（Claude Cowork 等）

```
1. MCP クライアントが MCP サーバーに接続
   POST https://mcp-auth.example.com/mcp
   Authorization: なし

2. idproxy が 401 を返す
   HTTP/1.1 401 Unauthorized
   WWW-Authenticate: Bearer resource_metadata="https://mcp-auth.example.com/.well-known/oauth-authorization-server"

3. MCP クライアントがメタデータを取得
   GET https://mcp-auth.example.com/.well-known/oauth-authorization-server

   レスポンス:
   {
     "issuer": "https://mcp-auth.example.com",
     "authorization_endpoint": "https://mcp-auth.example.com/authorize",
     "token_endpoint": "https://mcp-auth.example.com/token",
     "response_types_supported": ["code"],
     "grant_types_supported": ["authorization_code"],
     "code_challenge_methods_supported": ["S256"],
     "token_endpoint_auth_methods_supported": ["none"]
   }

4. MCP クライアントが認可リクエストを送信（PKCE 付き）
   - code_verifier を生成（43-128文字のランダム文字列）
   - code_challenge = BASE64URL(SHA256(code_verifier))

   GET https://mcp-auth.example.com/authorize?
     response_type=code&
     client_id=<dynamic-client-id>&
     redirect_uri=<client-callback>&
     code_challenge=<challenge>&
     code_challenge_method=S256&
     state=<random>&
     scope=openid

5. idproxy がプロバイダー選択 or 直接リダイレクト
   （ブラウザフローと同じ IdP 選択ロジック）

6. ユーザーが IdP で認証（ブラウザが開く）

7. IdP → idproxy /callback → idproxy が認証を検証

8. idproxy が認可コードを発行
   a. IdP の ID Token を検証
   b. AllowedDomains / AllowedEmails で認可判定
   c. 認可コードを生成（暗号論的乱数）
   d. AuthCodeData を Store に保存（code_challenge 含む）
   e. MCP クライアントの redirect_uri にリダイレクト
      302 → <client-callback>?code=<auth-code>&state=<state>

9. MCP クライアントがトークンリクエストを送信
   POST https://mcp-auth.example.com/token
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code&
   code=<auth-code>&
   redirect_uri=<client-callback>&
   client_id=<dynamic-client-id>&
   code_verifier=<verifier>

10. idproxy がトークンを発行
    a. 認可コードを Store から取得
    b. 認可コードの有効期限・使用済みチェック
    c. PKCE 検証: SHA256(code_verifier) == code_challenge
    d. Access Token（JWT）を署名・発行
       - iss: https://mcp-auth.example.com
       - sub: <oidc-subject>
       - email: <user-email>
       - aud: <client-id>
       - jti: <uuid>
       - iat, exp
    e. Store に AccessTokenData を保存
    f. 認可コードを使用済みにマーク

    レスポンス:
    {
      "access_token": "<jwt>",
      "token_type": "Bearer",
      "expires_in": 3600
    }

11. MCP クライアントが Bearer Token で MCP リクエスト
    POST https://mcp-auth.example.com/mcp
    Authorization: Bearer <jwt>
    Content-Type: application/json

    {"jsonrpc": "2.0", "method": "initialize", ...}

12. idproxy が Bearer Token を検証
    a. JWT 署名検証（公開鍵）
    b. クレーム検証（iss, exp, aud）
    c. Store でリボケーションチェック（オプション）
    d. ユーザー情報をコンテキストに注入
    e. next.ServeHTTP(w, r) → upstream MCP server へ
```

### フロー3: SSE パススルー

```
1. 認証済みリクエスト（Cookie or Bearer）が SSE エンドポイントにアクセス
   GET https://mcp-auth.example.com/mcp
   Accept: text/event-stream
   Authorization: Bearer <jwt>

2. idproxy が認証を検証（フロー1 or フロー2 と同じ）

3. 認証 OK → httputil.ReverseProxy が upstream に転送
   - FlushInterval: -1（即時フラッシュ）
   - upstream の Content-Type: text/event-stream をそのまま透過
   - Transfer-Encoding: chunked

4. upstream が SSE イベントを送信
   data: {"jsonrpc": "2.0", "result": ...}

5. ReverseProxy がイベントをクライアントにそのまま転送
   - バッファリングなし（FlushInterval: -1）
   - Content-Type ヘッダーもそのまま透過

6. 接続が閉じられるまで継続
   - クライアント側切断: ReverseProxy が検知して upstream 接続も閉じる
   - upstream 側切断: クライアントに EOF が送られる
```

---

## 9. Technical Constraints

### Go バージョン

- **Go 1.26 以上**
- `net/http` の ServeMux メソッドパターンマッチ（Go 1.22+）を活用
- `slog` 標準ロガー（Go 1.21+）を使用

### 依存ライブラリ

| ライブラリ | 用途 | バージョン | 代替不可の理由 |
|-----------|------|----------|-------------|
| `github.com/coreos/go-oidc/v3` | OIDC Discovery, ID Token 検証, JWK キャッシュ | v3.x | Go OIDC のデファクトスタンダード。Discovery + 検証を一括提供 |
| `golang.org/x/oauth2` | OAuth2 Authorization Code Flow | latest | Go 準標準。go-oidc が内部で依存 |
| `github.com/golang-jwt/jwt/v5` | JWT 署名・検証（Access Token 発行用） | v5.x | Go JWT のデファクトスタンダード |
| `github.com/gorilla/securecookie` | Cookie 暗号化（AES-GCM） | v1.x | 実績のある Cookie 暗号化ライブラリ |
| `github.com/google/uuid` | UUID v4 生成（セッション ID 等） | v1.x | 標準的な UUID ライブラリ |

### セキュリティ要件

| 要件 | 実装方法 |
|------|---------|
| CSRF 防止 | OIDC state パラメータ（暗号論的乱数） |
| リプレイ攻撃防止 | OIDC nonce パラメータ |
| セッション固定攻撃防止 | 認証成功時に新しいセッション ID を発行 |
| Cookie セキュリティ | `Secure`, `HttpOnly`, `SameSite=Lax` 属性 |
| JWT 署名 | ES256（推奨）or RS256。HS256 は禁止（共有秘密鍵のリスク） |
| PKCE | S256 のみ（plain は禁止、OAuth 2.1 準拠） |
| 認可コード一回使用 | 使用済みフラグを Store に記録、二重使用時は関連トークンを全て無効化 |
| 秘密鍵の管理 | 環境変数 or ファイルパスで注入。コードにハードコードしない |
| TLS | idproxy 自体は HTTP で動作し、前段のロードバランサー/リバースプロキシで TLS 終端を想定。ただし `EXTERNAL_URL` は `https://` 必須 |

---

## 10. Configuration

### 環境変数一覧（スタンドアロンモード）

| 環境変数 | 必須 | デフォルト | 説明 |
|---------|------|----------|------|
| `OIDC_ISSUER` | ○ | - | OIDC Issuer URL。カンマ区切りで複数指定可。例: `https://accounts.google.com,https://login.microsoftonline.com/{tenant}/v2.0` |
| `OIDC_CLIENT_ID` | ○ | - | OAuth Client ID。カンマ区切りで複数指定可（`OIDC_ISSUER` と位置で対応）|
| `OIDC_CLIENT_SECRET` | ○ | - | OAuth Client Secret。カンマ区切りで複数指定可（`OIDC_ISSUER` と位置で対応）|
| `UPSTREAM` | ○ | - | 上流サーバー URL。例: `http://localhost:3000` |
| `EXTERNAL_URL` | ○ | - | 外部公開 URL。`https://` 必須。例: `https://mcp-auth.example.com` |
| `COOKIE_SECRET` | ○ | - | Cookie 暗号化キー。32バイト以上の hex 文字列。`openssl rand -hex 16` で生成 |
| `JWT_SIGNING_KEY_FILE` | △ | - | JWT 署名用秘密鍵の PEM ファイルパス。OAuth 2.1 AS を使用する場合は必須 |
| `LISTEN_ADDR` | × | `:8080` | HTTP リッスンアドレス |
| `ALLOWED_DOMAINS` | × | - | 許可するメールドメイン。カンマ区切り。未設定時は全ドメイン許可 |
| `ALLOWED_EMAILS` | × | - | 許可する個別メールアドレス。カンマ区切り。`ALLOWED_DOMAINS` と OR 評価 |
| `SESSION_MAX_AGE` | × | `24h` | ブラウザセッションの最大有効期間。Go の `time.Duration` 形式 |
| `ACCESS_TOKEN_TTL` | × | `1h` | OAuth 2.1 Access Token の有効期間 |
| `AUTH_CODE_TTL` | × | `10m` | 認可コードの有効期間 |
| `LOG_LEVEL` | × | `info` | ログレベル（debug, info, warn, error） |
| `PATH_PREFIX` | × | `""` | OAuth 2.1 AS エンドポイントのパスプレフィックス |

### 環境変数のバリデーションルール

- `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` は同じ数のカンマ区切り要素を持つこと
- `EXTERNAL_URL` は `https://` で始まること（ローカル開発時は `http://localhost:*` を例外許可）
- `COOKIE_SECRET` は32バイト（64文字の hex）以上であること
- `JWT_SIGNING_KEY_FILE` が指定された場合、ファイルが存在し、有効な PEM 形式であること
- `SESSION_MAX_AGE`, `ACCESS_TOKEN_TTL`, `AUTH_CODE_TTL` は Go の `time.ParseDuration` でパース可能であること

### Config 構造体のデフォルト値

```go
var DefaultConfig = Config{
    SessionMaxAge:  24 * time.Hour,
    AccessTokenTTL: 1 * time.Hour,
    AuthCodeTTL:    10 * time.Minute,
    PathPrefix:     "",
}
```

各 `OIDCProvider` のデフォルト Scopes:

```go
var DefaultScopes = []string{"openid", "email", "profile"}
```

---

## 11. Directory Structure

```
idproxy/
├── go.mod                          # モジュール定義
├── go.sum                          # 依存ロックファイル
├── LICENSE                         # MIT or Apache 2.0
├── README.md                       # プロジェクト概要、クイックスタート
├── .goreleaser.yml                 # GoReleaser 設定
├── .github/
│   └── workflows/
│       ├── ci.yml                  # CI（テスト、lint、ビルド）
│       └── release.yml             # リリース（tag push → GoReleaser）
│
├── auth.go                         # Auth 構造体、New()、Wrap()、リクエスト判定ロジック
├── auth_test.go                    # Auth のユニットテスト
├── config.go                       # Config, OIDCProvider, OAuthConfig 構造体定義、バリデーション
├── config_test.go                  # Config バリデーションテスト
├── oauth2.go                       # OAuth 2.1 AS エンドポイント（authorize, token, callback, well-known）
├── oauth2_test.go                  # OAuth 2.1 フローのテスト
├── session.go                      # SessionManager、Cookie 管理、暗号化 JWT
├── session_test.go                 # セッション管理テスト
├── store.go                        # Store インターフェース定義、Session/AuthCodeData/AccessTokenData 型
├── user.go                         # User 構造体、UserFromContext()
├── provider.go                     # OIDC プロバイダー管理、Discovery、IdP 選択ロジック
├── provider_test.go                # プロバイダーテスト
├── pkce.go                         # PKCE ユーティリティ（S256 チャレンジ生成・検証）
├── pkce_test.go                    # PKCE テスト
│
├── store/
│   ├── memory.go                   # MemoryStore 実装
│   └── memory_test.go              # MemoryStore テスト
│
├── cmd/
│   └── idproxy/
│       ├── main.go                 # スタンドアロンバイナリのエントリポイント
│       └── main_test.go            # 環境変数パース等の統合テスト
│
├── examples/
│   ├── basic/
│   │   └── main.go                 # 最小構成のライブラリ使用例
│   └── mcp-server/
│       └── main.go                 # mcp-go との統合例
│
├── testutil/                       # テストヘルパー（モック IdP サーバー等）
│   └── mock_idp.go                 # テスト用 OIDC IdP モック
│
└── docs/
    └── specs/
        └── idproxy-spec.md         # 本スペック文書
```

---

## 12. Release Strategy

### リリースフロー

1. **開発**: `main` ブランチで開発
2. **バージョニング**: Semantic Versioning（`v0.x.x` から開始、1.0.0 は安定版）
3. **タグ付け**: `git tag v0.1.0 && git push --tags`
4. **CI/CD**: GitHub Actions が tag push をトリガーに GoReleaser を実行
5. **成果物**: GitHub Releases にバイナリ + チェックサムをアップロード

### GoReleaser で生成する成果物

| OS | Arch | ファイル名 |
|----|------|----------|
| Linux | amd64 | `idproxy_linux_amd64.tar.gz` |
| Linux | arm64 | `idproxy_linux_arm64.tar.gz` |
| macOS | amd64 | `idproxy_darwin_amd64.tar.gz` |
| macOS | arm64 | `idproxy_darwin_arm64.tar.gz` |
| Windows | amd64 | `idproxy_windows_amd64.zip` |

### リリースフェーズ

| フェーズ | バージョン | 対象 | 条件 |
|---------|----------|------|------|
| 開発 | v0.0.x | 自分のみ | - |
| クローズドβ | v0.1.0 | heptagon 社内 | 社内 MCP server 1台で動作確認済み |
| パブリック | v0.2.0+ | 全ユーザー | README、examples、基本テスト完備 |
| 安定版 | v1.0.0 | 全ユーザー | API の後方互換性を保証 |

---

## 13. Phased Implementation Plan

### Phase 1: MVP（目標: 2-3週間）

#### Step 1: プロジェクト初期化・Config（2日）
- [ ] リポジトリ作成、go.mod 初期化
- [ ] Config, OIDCProvider, OAuthConfig 構造体定義
- [ ] Config バリデーション実装・テスト
- [ ] 環境変数パーサー実装（cmd/idproxy）

#### Step 2: Store インターフェース・MemoryStore（1日）
- [ ] Store インターフェース定義
- [ ] Session, AuthCodeData, AccessTokenData 型定義
- [ ] MemoryStore 実装（TTL 付き、バックグラウンドクリーンアップ）
- [ ] MemoryStore テスト

#### Step 3: OIDC 認証・ブラウザフロー（3日）
- [ ] OIDC プロバイダー管理（Discovery、複数 IdP 対応）
- [ ] OIDC Authorization Code Flow 実装
- [ ] コールバック処理（ID Token 検証、認可判定）
- [ ] Cookie セッション管理（gorilla/securecookie）
- [ ] プロバイダー選択ページ（複数 IdP 時）
- [ ] テスト（モック IdP 使用）

#### Step 4: Auth ミドルウェア・Wrap()（2日）
- [ ] Auth 構造体、New() 関数
- [ ] Wrap() メソッド（リクエスト判定ロジック）
- [ ] UserFromContext() 実装
- [ ] Bearer Token 検証（JWT）
- [ ] Cookie セッション検証
- [ ] テスト

#### Step 5: OAuth 2.1 Authorization Server（3日）
- [ ] RFC 8414 メタデータエンドポイント
- [ ] /authorize エンドポイント（PKCE 対応）
- [ ] /callback エンドポイント（認可コード発行）
- [ ] /token エンドポイント（PKCE 検証、JWT 発行）
- [ ] PKCE ユーティリティ（S256）
- [ ] テスト

#### Step 6: スタンドアロンプロキシ（1日）
- [ ] cmd/idproxy/main.go 実装
- [ ] httputil.ReverseProxy + FlushInterval:-1
- [ ] 環境変数からの Config 構築
- [ ] ヘルスチェックエンドポイント（/healthz）

#### Step 7: 統合テスト・ドキュメント（2日）
- [ ] E2E テスト（モック IdP + テスト upstream）
- [ ] mcp-go 統合テスト
- [ ] README.md 作成
- [ ] examples/ 作成（basic, mcp-server）
- [ ] GoReleaser 設定
- [ ] GitHub Actions CI/CD

### Phase 2: 安定化（目標: 1-2週間）

- [ ] Redis Store 実装
- [ ] 構造化監査ログ
- [ ] Prometheus メトリクス（/metrics）
- [ ] トークンリフレッシュ対応
- [ ] エラーページのカスタマイズ

### Phase 3: 拡張（目標: 1ヶ月）

- [ ] グループベースアクセス制御（OIDC groups クレーム）
- [ ] 動的クライアント登録（RFC 7591）
- [ ] トークンリボケーションエンドポイント（RFC 7009）
- [ ] JWKS エンドポイント（/.well-known/jwks.json）

---

## 14. Open Questions

- [ ] ライセンスは MIT と Apache 2.0 のどちらにするか
- [ ] 複数プロバイダー時の IdP 選択 UI のデザイン（シンプルな HTML ページ or JSON レスポンスで選択肢を返す）
- [ ] MCP OAuth 2.1 の Dynamic Client Registration（RFC 7591）は MVP に含めるべきか（Claude Cowork の実装次第）
- [ ] JWT 署名アルゴリズムのデフォルトは ES256 と RS256 のどちらにするか（ES256 推奨だが EntraID との互換性を確認）
- [ ] ALLOWED_DOMAINS も ALLOWED_EMAILS も未設定の場合の挙動（全員許可 or 全員拒否）
- [ ] ログインページ（IdP 選択）のカスタマイズ性をどこまで提供するか

---

## 15. Changelog

| 日時 | 内容 |
|------|------|
| 2026-04-08 | 初版作成 |
