# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- feat(store): SQLite Store を追加（`store/sqlite`）
  - 単一ノードでのファイルベース永続化に適する。`modernc.org/sqlite` を使用するため CGO 不要
  - `:memory:` でテスト用途も対応
  - ConsumeRefreshToken はトランザクション + `used=0` CAS で atomic に実装
- feat(store): Redis Store を追加（`store/redis`）
  - go-redis v9 ベース。汎用分散 KV による複数インスタンス間状態共有向け
  - ConsumeRefreshToken は埋め込み Lua script (`consume.lua`) で atomic に実装
  - native TTL に委譲するため `Cleanup()` は no-op
- feat(store): 適合性テストスイート `store/storetest` を追加。全 Store 実装で共通の挙動を保証
- feat(cmd): `STORE_BACKEND` 環境変数で Store バックエンドを選択可能に
  - `memory` (default) / `dynamodb` / `sqlite` / `redis`
  - DynamoDB 切替も本リリースでバイナリから初対応（従来はライブラリ API のみ）
  - 各バックエンドの env 仕様は `idproxy --help` または README 参照
- feat(provider): Amazon Cognito User Pool を公式サポート対象に追加
  - `cognito-idp.<region>.amazonaws.com` 形式の Issuer を `Amazon Cognito` として自動表示
  - knownIssuers を完全一致 map + 正規表現パターン slice に拡張（順序保持・将来拡張容易）
- feat(browser_auth): ID Token の `name` クレーム未設定時に fallback を導入
  - 1) `cognito:username`（Amazon Cognito）→ 2) `preferred_username`（OIDC 標準）
  - 既存 IdP（`name` クレーム提供）には影響なし
- feat(testutil): `MockIdP.SetExtraClaims(map[string]any)` を追加
  - `cognito:username` 等の IdP 固有クレームをテストで再現可能に

## [v0.3.1] - 2026-04-20

### Added

- feat(oauth): refresh_token rotation の可観測性向上
  - rotation 成功時に `slog.Info("oauth refresh rotation", "family_id", ..., "client_id", ..., "scope", ...)` を出力
  - 既存の replay 検知ログ `slog.Warn("oauth refresh replay detected", ...)` と対称なイベントペアを形成
  - refresh_token 文字列はログに含めない（テストで強制）

### Changed

- docs: refresh_token rotation の設計意図（`Used=true` 方式採用理由）を README / README_ja / CLAUDE.md に明文化
  - OAuth 2.1 §4.3.2 "MUST invalidate" を「delete」ではなく「mark as used」で満たす設計
  - replay 検知時に `FamilyID` を取り出して family 全体を revoke するため旧トークンレコードを保持
  - 本番 DynamoDB 観察時に `used` 属性を projection する運用手順を追記

### Notes

- **挙動変更なし** — ログ追加とドキュメント明文化のみ
- 既存 refresh_token テスト（T5 / T8 / T12 等）に回帰なし

## [v0.3.0] - 2026-04-19

### Added

- feat(oauth): OAuth 2.1 `refresh_token` grant type を実装
  - `grant_type=refresh_token` による access_token 再発行（OAuth 2.1 §4.3.2 rotation 準拠）
  - 各 authorization_code フローから派生する全 refresh_token を共通 `FamilyID` で追跡
  - replay 検知時に同一 family の全 refresh_token を自動無効化（tombstone レコード方式）
  - refresh_token は opaque 32 バイト（base64url）、JWT ではなく Store 管理
  - Discovery メタデータ `grant_types_supported` に `"refresh_token"` を追加
  - DCR 応答の `grant_types` に `"refresh_token"` を追加
- feat(config): `Config.RefreshTokenTTL` を追加（デフォルト: 30 日）
- feat(store): `Store` interface に 5 メソッド追加
  - `SetRefreshToken` / `GetRefreshToken` / `ConsumeRefreshToken` / `SetFamilyRevocation` / `IsFamilyRevoked`
  - `MemoryStore` と `DynamoDBStore` 両方で実装
- feat(oauth): `/authorize` と `/token` エンドポイントに構造化診断ログを追加
  - `slog.Info("oauth authorize", ...)` / `slog.Info("oauth token", ...)`
  - replay 検知時: `slog.Warn("oauth refresh replay detected", ...)`

### Fixed

- fix(oauth): `Config.AccessTokenTTL` が無視されていたバグを修正
  - `oauth_server.go` で access_token TTL が `time.Hour` にハードコードされていたため、`Config.AccessTokenTTL` 設定値が反映されていなかった
  - 設定値が正しく access_token の `exp` クレームと Store TTL に適用されるようになった

## [v0.2.0] - 2026-04-17

### Added

- feat(store): DynamoDB Store 実装追加 — Lambda マルチインスタンス環境対応
  - `store.NewDynamoDBStore(tableName, region string)` — 本番用コンストラクタ
  - `store.NewDynamoDBStoreWithClient(client, tableName)` — テスト用モック注入コンストラクタ
  - 単一テーブル設計: PK プレフィクスで Session / AuthCode / AccessToken / Client を名前空間分離
  - DynamoDB TTL ラグ対策: Get 時に `ttl` 属性と現在時刻を比較し期限切れなら `(nil, nil)` 返却
  - ConsistentRead: `GetSession` / `GetAuthCode` に適用 (Lambda マルチコンテナ race 対策)
  - `Cleanup()` は no-op — DynamoDB TTL に委譲
  - `Close()` は冪等 (`sync.Once` + `atomic.Bool`)
  - 閉塞後の操作は `errDynamoDBStoreClosed` を返す
