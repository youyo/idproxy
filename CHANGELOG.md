# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
