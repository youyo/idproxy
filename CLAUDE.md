# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## プロジェクト概要

idproxy は **OIDC 認証リバースプロキシ + MCP 向け OAuth 2.1 Authorization Server** を単一の Go ライブラリ／バイナリとして提供する。任意の HTTP バックエンドの前段に配置し、OIDC ブラウザ認証と OAuth 2.1 Bearer Token 検証を透過的に処理する。Dynamic Client Registration (RFC 7591)・SSE 透過プロキシ対応で、MCP サーバー保護を主用途として想定。

ライブラリ（`github.com/youyo/idproxy`）・スタンドアロンバイナリ（`cmd/idproxy`）の両方から使用できる。Go 1.26 以上。

## 開発コマンド

```bash
# ユニットテスト（race + カバレッジ）
go test -race -cover ./...

# 統合テスト（build tag: integration）
go test -race -tags=integration ./...

# 単一パッケージ／単一テスト実行
go test -run TestName ./path/to/pkg

# ビルド
go build ./cmd/idproxy/...

# Lint（CI と同じバージョン: golangci-lint v2.11.4）
golangci-lint run
```

DynamoDB Store のテストは全て mock ベース（`store/dynamodb_test.go` 参照）。モック IdP は `testutil/mock_idp.go`、モック MCP サーバーは `testutil/mock_mcp.go`。

## リリースフロー

- `main` への push → CI（test + lint + build）
- `v*` タグを push → CI 成功後に Release ワークフロー（GoReleaser）が `workflow_run` で自動起動
- GoReleaser 設定は `.goreleaser.yml`。linux/darwin/windows × amd64/arm64 のバイナリ、Homebrew tap（`youyo/homebrew-tap`）、checksums を生成

## アーキテクチャ

### エントリーポイントと認証ディスパッチ

`idproxy.New(ctx, cfg)` が中心エントリ。`Auth.Wrap(next http.Handler)` で任意の `http.Handler` をラップする（`auth.go`）。Wrap 内では以下の順序でリクエストを分岐する：

1. **BrowserAuth パス**（`{prefix}/login`・`/callback`・`/select`）→ `BrowserAuth` に委譲
2. **OAuth 2.1 AS パス**（`/.well-known/*`・`/register`・`/authorize`・`/token`）→ `oauthServer` に委譲。未設定時は 501
3. **Authorization: Bearer** ヘッダー → `BearerValidator.Validate()` で JWT 検証
4. **セッション Cookie** → `SessionManager.GetSessionFromRequest()` で復号・検証
5. **ブラウザリクエスト**（`Accept: text/html`）→ `{prefix}/login` へリダイレクト
6. **API リクエスト** → 401

認証成功時は `UserFromContext(ctx)` で取得できるよう `newContextWithUser()` で `*User` を注入。

### コンポーネント構成

- `config.go` — `Config`・`OIDCProvider`・`OAuthConfig`。`Config.Validate()` がデフォルト値適用とバリデーションを兼ねる。使用前に必ず呼び出すこと（`New()` 内で呼ばれる）
- `provider.go` — `ProviderManager`: 複数 OIDC プロバイダーの Discovery とキャッシュ。複数設定時は `/select` で選択ページを提示
- `session.go` — `SessionManager`: `gorilla/securecookie` で暗号化した Cookie + `Store` での永続化
- `browser_auth.go` — `/login` → IdP → `/callback` のフロー処理。`state` パラメータを一時的な `AuthCodeData` として Store に格納する独特の再利用がある
- `oauth_server.go` — OAuth 2.1 AS 本体。メタデータ・`/authorize`・`/token`・`/register`（DCR）を実装
- `bearer.go` — JWT Bearer トークン検証（ES256 固定、`Store` でリボケーション確認）
- `pkce.go` — PKCE S256 コードチャレンジ生成・検証
- `cmd/idproxy/` — 環境変数駆動のスタンドアロンバイナリ。`httputil.NewSingleHostReverseProxy` + `FlushInterval: -1` で SSE 透過

### Store インターフェース

`store.go` で定義。セッション・認可コード・アクセストークン・動的登録クライアントの永続化を抽象化。

- **`store/memory.go`** — `MemoryStore`: デフォルト実装。5分間隔の `time.Ticker` で自動クリーンアップ。単一インスタンス向け
- **`store/dynamodb.go`** — `DynamoDBStore`: Lambda マルチコンテナ等の多インスタンス環境向け（v0.2.0 以降）
  - 単一テーブル設計。PK プレフィクス（`session#`・`authcode#` 等）で名前空間を分離
  - `Cleanup()` は no-op（DynamoDB TTL に委譲）。ただし TTL 最大 48 時間のラグに備え、`Get` 系で `ttl` 属性を現在時刻と比較して期限切れは `(nil, nil)` を返す
  - `GetSession`・`GetAuthCode` では `ConsistentRead` を有効化（マルチコンテナ race 対策）
  - `Close()` は `sync.Once` + `atomic.Bool` で冪等。閉塞後の操作は `errDynamoDBStoreClosed`
  - `NewDynamoDBStoreWithClient(client, tableName)` でモックを注入可能

### 設計上の前提

- **JWT 署名は ES256 固定**（Bearer Validator は ECDSA 秘密鍵のみ受け付ける）。RSA を使う場合は `OAuthConfig.SigningMethod` を明示する想定だが、Bearer 側で未対応
- **PKCE は S256 のみ**（OAuth 2.1 推奨に従う）
- **未設定時は全ユーザー許可** — `AllowedDomains`・`AllowedEmails` を両方空にすると OIDC 認証が通れば全員許可（仕様上の設計判断）
- **ExternalURL は `https://` 必須**。例外は `http://localhost`・`127.0.0.1`・`::1`
- **CookieSecret は 32 バイト以上**（HMAC hash key としてそのまま使用）

## 計画とドキュメント

- `plans/idproxy-roadmap.md` — 全マイルストーン（M01〜M21）の進捗。現在は M21（DynamoDB Store v0.2.0）まで完了
- `plans/idproxy-m*.md` — 各マイルストーンの詳細計画
- `docs/specs/` — プロダクト仕様書
- `README.md`（英語）・`README_ja.md`（日本語）— ユーザー向けドキュメント。ソースコード内コメントは全て日本語

## コーディング規約

- **ソースコード内コメントは日本語**（既存コードに揃える）
- **README は英語**（`README.md`）と日本語（`README_ja.md`）の 2 バージョン
- **TDD: Red → Green → Refactor** を基本サイクルとする。テストファイルは `*_test.go` で同パッケージに配置
- **`errcheck` を厳格に扱う** — `fmt.Fprintf` 等の戻り値を捨てる場合は `_ =` で明示的に discard（過去に CI でエラー頻発している）
- **ブランチ命名: 単一文字の前にハイフン禁止**（例: `fix-f-encoding` NG、`fix-japanese-filename-encoding` OK）
- **コミットメッセージは Conventional Commits（日本語）**
