# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- feat(config): `OnAuthenticated` フック / `DefaultPostLoginPath` / `PostLoginRedirectValidator` を `Config` に追加
  - ゼロ値で v0.4.2 までの動作維持（純粋 API 追加、SemVer minor bump 互換）
  - `OnAuthenticated` は認証完了直後（セッション発行直後）に同期で呼ばれる。フック内 panic は recover して 500 を返す
  - `OnAuthenticated` の戻り値 `(redirectTo, handled)` 4 状態の挙動は godoc に明文化
- feat(config): `StrictPostLoginRedirectValidator(externalURL)` helper と `(*Config).UseStrictPostLoginRedirectValidator()` setter を公開
  - 同一 origin の絶対 URL および相対パスのみを許可。多段検査（TrimSpace / unicode.IsControl|Cf / 構造文字 / NFKC 正規化 / url.Parse）で `javascript:` / `data:` / protocol-relative / backslash / 同形異字攻撃を拒否
  - opt-in 推奨。既存利用者の動作は壊さない
- feat(store/redis): `WithClientOwnership(bool)` Option を追加
  - `NewWithClient(client, keyPrefix string, opts ...Option)` に末尾可変引数を追加（既存 2 引数呼び出しは引き続き有効）
  - デフォルトは `ownsClient=true`（v0.4.2 まで互換）。外部注入 client を Close したくない場合は `WithClientOwnership(false)` を渡す

### Security

- security: `redirect_to` クエリの URL escape および Validator 適用を全リダイレクト入口で統一
  - `Auth.handleUnauthenticated`: 元 URL を `url.QueryEscape` してから loginURL に連結（escape 漏れ修正）
  - `BrowserAuth.SelectionHandler`: 同上、Validator 適用
  - `BrowserAuth.LoginHandler` / `OAuthServer.redirectToLogin`: `PostLoginRedirectValidator` を適用
  - `OnAuthenticated` フック戻り値の `redirectTo` も Validator を通す
  - Validator が non-nil のときは reject で 400（入力起因）。フック戻り値起因は 500
  - Validator panic は BrowserAuth 側で recover して 500（`http.ErrAbortHandler` のみ再 panic）

### Documentation

- docs: post-login redirect 挙動・カスケード OAuth パターン・Store 共存・middleware migration ガイドを README / README_ja / `doc.go` に追加
- docs: `docs/store-coexistence.md` を新規作成（Client ownership matrix、DynamoDB 単一テーブル共存、Redis prefix 分離、SQLite 制約と将来計画、shutdown 順序）
- docs: `docs/cascade-oauth-pattern.md` を新規作成（責務分割・state 管理・トークン保存先選定・失敗時フロー・セキュリティチェックリスト・anti-patterns）
- docs(store): `DynamoDB Store` の godoc に「注入 client は Close で閉じない（AWS SDK v2 慣習）」を明文化
- docs(examples): `examples/cascade-oauth` と `examples/dynamodb-coexist` を新規追加
  - cascade-oauth: `OnAuthenticated` で外部 OAuth 接続状態を分岐する最小サンプル + migration 例
  - dynamodb-coexist: idproxy と利用側業務データを同一 DynamoDB テーブルで共存させるサンプル + `table.json` + 最小 IAM ポリシー
- ci: `.github/workflows/ci.yml` の build job に `go build ./examples/...` と `go test ./examples/...` を追加

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
