# Store バックエンド拡張 + Cognito 公式サポート

> **実装結果との差分（2026-04-29 追記）**:
> - **Momento は本 PR で見送り**: deprecated SDK API・重い transitive 依存・`SetIfEqual` の TTL/CAS 制約に起因するレビュー指摘多発のため、PR レビュー過程で削除を決定。実装範囲は **SQLite / Redis の 2 種**。
> - **Go module 構成は単一 `go.mod` 維持**: 計画書では「各バックエンドを個別 Go module 化 + `go.work` でトップレベル管理」を推奨していたが、依存追加コストの実測と運用シンプルさを優先し、単一 `go.mod` に依存を追加する形に変更。ライブラリ利用者がドライバ依存を引かない構造は、ビルドタグや別パッケージ分離で同等に実現できると判断。
>
> 以下の本文は計画策定時のスナップショット。

## Context

idproxy は分散環境（Lambda マルチコンテナ等）向けの永続化として現状 `MemoryStore` と `DynamoDBStore` の 2 実装を持つ。`Store` インターフェースは `store.go:14-49` に定義された 13 メソッド構成（Session / AuthCode / AccessToken / Client / RefreshToken / FamilyRevocation + Cleanup / Close）。

しかし以下のギャップがある:

1. ライブラリ利用者の選択肢が DynamoDB しかなく、AWS 以外（GCP / オンプレ / Kubernetes）での分散運用が困難。
2. `cmd/idproxy/config.go:109` は `store.NewMemoryStore()` 固定で、**バイナリから DynamoDB すら選択できない**（ライブラリ API 経由でのみ利用可）。
3. OIDC プロバイダーは設計上 EntraID / Google に限定されないが、knownIssuers (`provider.go:196-217`) や README で公式言及があるのは 2 つのみ。Cognito (cognito-idp.{region}.amazonaws.com) を公式サポートに加える需要がある。

本変更で **Store バックエンドを 3 種追加**（SQLite / Redis / Momento）し、`STORE_BACKEND` 環境変数 + 個別 env で `cmd/idproxy` バイナリから選択可能にする。PostgreSQL / MySQL は本 PR から除外（将来追加可能な構造のみ用意）。同 PR で Cognito を公式サポート（knownIssuers 追加・クレーム fallback・mock IdP 拡張・README 追記）に組み込む。

### バックエンド選定理由

| バックエンド | 用途 |
|---|---|
| Memory（既存） | テスト・開発 |
| DynamoDB（既存） | AWS 分散環境 |
| SQLite（追加） | 単一ノード永続化（CGO 不要、ファイルベース） |
| Redis（追加） | 汎用分散 KV |
| Momento（追加） | サーバーレス分散 KV（運用負荷低） |

全追加バックエンドが KV 系のため SQL Dialect 抽象が不要となり、実装が単純化する。

## アーキテクチャ方針

### サブモジュール分離（推奨採用）

各バックエンドは個別 Go module として配置する。理由はライブラリ利用者が不要なドライバ依存（modernc.org/sqlite, go-redis, momento SDK）を pull させないため。

```
store/sqlite/     (go.mod, modernc.org/sqlite)
store/redis/      (go.mod, github.com/redis/go-redis/v9)
store/momento/    (go.mod, github.com/momentohq/client-sdk-go)
store/storetest/  (go.mod, 全実装で共有する適合性テストスイート)
```

トップレベルに `go.work` を置き、ローカル開発・CI で全モジュールを統合する。`cmd/idproxy` は全サブモジュールを require し、バイナリにすべてのバックエンドを同梱。

既存 `store/dynamodb.go` と `store/memory.go` は本 PR では破壊的に動かさず、本体パッケージ内に維持。将来別 module 化を検討（v0.4.0 マイルストーンで）。

### SQLite スキーマ

エンティティごとに 6 テーブル: `sessions`, `auth_codes`, `access_tokens`, `clients`, `refresh_tokens`, `family_revocations`。共通カラム:

| カラム | 型 | 用途 |
|---|---|---|
| `key` | TEXT PRIMARY KEY | エンティティ ID |
| `data` | TEXT (JSON シリアライズ) | エンティティ本体 |
| `expires_at` | INTEGER (Unix epoch) | TTL（NULL は無期限：clients のみ） |
| `updated_at` | INTEGER (Unix epoch) | 監査用 |

`expires_at` に index。`database/sql` + modernc.org/sqlite を直接使用、Dialect 抽象は導入しない。

### TTL 戦略

| 実装 | 戦略 |
|---|---|
| SQLite | GET 時に `WHERE expires_at IS NULL OR expires_at > ?` フィルタ + 5 分周期 Cleanup ゴルーチン（`memory.go:66-77` の `cleanupLoop` パターンを移植） |
| Redis | `SET key value EX <seconds>` で native TTL |
| Momento | SDK の TTL オプションで native |

### CAS（ConsumeRefreshToken）実装

| 実装 | 方式 |
|---|---|
| SQLite | `UPDATE refresh_tokens SET data=?, updated_at=? WHERE key=? AND json_extract(data,'$.used')=0 RETURNING data`。0 行なら別 SELECT で `family_id` 抽出し `ErrRefreshTokenAlreadyConsumed` と共に返す。 |
| Redis | Lua script (`consume.lua`) で GET → 検証 → SET を atomic に。replay 時は family_id を Lua から返却。 |
| Momento | `SetIfEqual(prevSerialized)` で optimistic CAS。SDK が未対応版の場合は値内に version を埋め込み GET → SET を 3 回まで retry。CAS の弱さは README に明記。 |

`store/dynamodb.go` の ConditionExpression 実装（`store/dynamodb.go:22-74` 周辺）が参考実装。

## cmd/idproxy 設定（STORE_BACKEND + 個別 env）

`cmd/idproxy/config.go:109` の `cfg.Store = store.NewMemoryStore()` を `loadStore()` 関数化し switch:

```
STORE_BACKEND ∈ {memory(default), dynamodb, sqlite, redis, momento}
```

| バックエンド | 必要 env |
|---|---|
| memory | （なし） |
| dynamodb | `DYNAMODB_TABLE_NAME`, `AWS_REGION` |
| sqlite | `SQLITE_PATH`（既定 `:memory:`） |
| redis | `REDIS_ADDR`, `REDIS_PASSWORD`(opt), `REDIS_DB`(opt), `REDIS_TLS`(opt) |
| momento | `MOMENTO_AUTH_TOKEN`, `MOMENTO_CACHE_NAME`, `MOMENTO_DEFAULT_TTL`(opt) |

DynamoDB 切替も本 PR でバイナリに正式に組み込む（現状ライブラリ API 専用）。`printUsage()` も同期更新。

## Cognito 公式サポート

1. **knownIssuers 拡張** (`provider.go:196-217`): 現在 `map[string]string` で完全一致。`cognito-idp.<region>.amazonaws.com/<user-pool-id>` はリージョン・User Pool で動的なので、map → ordered slice + regex マッチに変更。`cognito-idp\.[a-z0-9-]+\.amazonaws\.com/.+` → "Amazon Cognito"。
2. **クレーム fallback** (`browser_auth.go:240-248`): 現状 `email`・`name` 固定。Cognito は `name` 未設定で `cognito:username` がある場合あり → name が空なら `cognito:username` を fallback として使用。
3. **mock IdP 拡張** (`testutil/mock_idp.go`): `WithExtraClaims(map[string]any)` オプション追加（汎用化）。テストで `cognito:username`, `cognito:groups` を ID Token に含めるケースを 1 件追加。
4. **README**: `README.md`, `README_ja.md`, `cmd/idproxy/README.md`(あれば) に Cognito User Pool 設定セクション追記。Issuer URL 形式・App Client・scope（openid / email / profile）・コールバック URL 設定例。

## 実装ステップ（TDD）

1. **Red — 適合性テストスイート抽出**: `store/storetest/conformance.go` に 13 メソッド + TTL + CAS + Close 冪等性をテーブル駆動で網羅。既存 `store/memory_test.go`・`store/dynamodb_test.go` から共通テストを抽出し両者を新スイートで置き換え（既存のテストカバレッジを維持していることを確認）。
2. **Green — SQLite**: `store/sqlite/store.go` を modernc.org/sqlite + `database/sql` 直書きで実装。CGO 不要なので CI で常時実行。`:memory:` で conformance スイートを通す。
3. **Green — Redis**: `miniredis` で単体テスト、testcontainers で integration。`consume.lua` をファイル化し `embed.FS` で同梱。
4. **Green — Momento**: SDK の fake / モックで単体、本物は integration（オプショナル：`MOMENTO_TEST_TOKEN` がある時のみ）。
5. **cmd/idproxy 統合**: `loadStore()` を関数化しテーブル駆動テスト追加。`printUsage()` 更新。**DynamoDB の env 切替もここで初実装**。
6. **Cognito**: `provider_test.go` に Cognito issuer 判定テスト、`browser_auth_test.go` にクレーム fallback テスト追加。`testutil/mock_idp.go` 拡張。
7. **Docs**: `README.md` / `README_ja.md` に Store バックエンド比較表 + Cognito セクション追記。`CHANGELOG.md` 更新。`plans/idproxy-roadmap.md` に M22 として追記。

## 修正・新規ファイル

**新規:**

- `store/sqlite/{go.mod, store.go, store_test.go, schema.sql}`
- `store/redis/{go.mod, store.go, store_test.go, consume.lua}`
- `store/momento/{go.mod, store.go, store_test.go}`
- `store/storetest/{go.mod, conformance.go}`
- `go.work`
- `docker-compose.test.yaml`（Redis 用、Momento は integration token 注入のみ）

**修正:**

- `cmd/idproxy/config.go`（`loadStore()` 追加、`printUsage()` 更新）
- `cmd/idproxy/config_test.go`（env テーブル）
- `cmd/idproxy/main.go`（必要なら import）
- `provider.go:196-217`（knownIssuers regex 化）
- `provider_test.go`（Cognito issuer マッチ）
- `browser_auth.go:240-248`（cognito:username fallback）
- `browser_auth_test.go`
- `testutil/mock_idp.go`（`WithExtraClaims` 追加）
- `README.md`, `README_ja.md`
- `CHANGELOG.md`
- `plans/idproxy-roadmap.md`

## 既存と再利用すべき関数

- `store.go:14-49` — `Store` interface 契約（13 メソッド）
- `store/memory.go:66-77` の `cleanupLoop` — sqlcommon Cleanup ゴルーチンの参照実装
- `store/memory.go` 全体 — TTL チェック・Closeable パターン
- `store/dynamodb.go:22-74` — Client 注入 New 関数の命名規則（`NewXxxStoreWithClient`）
- `store/dynamodb.go` の ConsumeRefreshToken ConditionExpression — SQL CAS / Redis Lua の参照
- `cmd/idproxy/config.go:45-85` — env パース・カンマ区切り処理（`splitTrim` 再利用）
- `provider.go:196-217` — knownIssuers
- `testutil/mock_idp.go` — クレームカスタマイズ拡張ベース

## リスクとトレードオフ

- **サブモジュール化のコスト**: go.work と CI matrix、リリースタグ運用が複雑化。代替の build tag 方式は go.mod 肥大化＋利用者への強制依存があるため不採用。
- **Momento の CAS 不完全性**: 真の CAS 不在。replay 検出に微小レース窓 → README に明示。本番分散運用は Redis / RDB / DynamoDB 推奨と記載。
- **CI 時間**: testcontainers (Redis) は integration tag に限定し nightly のみ実行。SQLite (`:memory:`) と miniredis で大半の単体テストを CI 常時実行可。
- **PostgreSQL / MySQL の将来追加**: 本 PR では除外。追加時は `store/sqlcommon/` に Dialect 抽象を導入し SQLite を移行する経路を想定（v0.5.0 以降）。
- **knownIssuers の O(1) → O(n)**: regex 化でルックアップが線形化するがエントリ数小（数件）で許容。
- **DynamoDB env を本 PR で初実装**: 既存ユーザーには影響なし（新規 env 追加のみ）が、リリースノートで明記。
- **依存追加サイズ**: メインモジュールには直接追加しないため、ライブラリ単体利用者の go.sum は変化なし。

## 検証

- 単体: `go test -race -cover ./...`（go.work で全モジュール一括）
- 統合: `docker-compose -f docker-compose.test.yaml up -d` 後 `go test -race -tags=integration ./...`
- Lint: `golangci-lint run ./...`（v2.11.4）
- 手動 E2E: `docker-compose up` で各 STORE_BACKEND を起動 → mock IdP / 実 IdP（Cognito User Pool）でログイン疎通 → access_token 取得 → refresh rotation → replay 検知（family revoke）まで一連を確認
- Cognito 実機: 任意のリージョンで User Pool + App Client を作成し、`OIDC_ISSUER=https://cognito-idp.<region>.amazonaws.com/<user-pool-id>` でログイン疎通確認
- README 手順を実行して再現性を担保
