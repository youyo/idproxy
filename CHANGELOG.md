# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
