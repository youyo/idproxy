# Roadmap: idproxy

## Meta
| 項目 | 値 |
|------|---|
| ゴール | OIDC 認証 + MCP OAuth 2.1 AS + SSE 透過を単一 Go バイナリ/ライブラリで提供 |
| 成功基準 | 社内 MCP server が idproxy 経由で認証付き公開、Claude Desktop/Cowork から OAuth 2.1 接続成功 |
| 制約 | Go 1.26+、外部依存最小（go-oidc, golang-jwt, securecookie, uuid）、1インスタンス1upstream |
| 対象リポジトリ | /Users/youyo/src/github.com/youyo/idproxy |
| 作成日 | 2026-04-08 |
| 最終更新 | 2026-04-08 17:10 |
| ステータス | 未着手 |

## Design Decisions (from Interview)
| # | 決定 | 理由 |
|---|------|------|
| 1 | MIT ライセンス | Go OSS の慣例に合致、シンプル |
| 2 | ALLOWED_DOMAINS/EMAILS 未設定時は全員許可 | OIDC 認証が通ればアクセス可能。直感的 |
| 3 | ES256 をデフォルト署名アルゴリズム | 鍵サイズ小・高速、OAuth 2.1 推奨 |
| 4 | Dynamic Client Registration (RFC 7591) を MVP に含める | Claude Cowork 互換に実用上必須 |

## Current Focus
- **マイルストーン**: M10 OIDC プロバイダー管理
- **直近の完了**: M09 セッション管理
- **次のアクション**: ProviderManager 構造体・OIDC Discovery 実装

## Progress

### M01: プロジェクト初期化
- [x] go.mod 初期化（Go 1.26、依存は M02 以降で追加）
- [x] ディレクトリ構造作成（store/, cmd/idproxy/, testutil/, examples/）
- [x] MIT LICENSE ファイル作成
- 📄 詳細: plans/idproxy-m01-project-init.md

### M02: 基本型定義
- [x] Config, OIDCProvider, OAuthConfig 構造体
- [x] User 構造体、UserFromContext()
- [x] Store インターフェース
- [x] Session, AuthCodeData, AccessTokenData 型
- 📄 詳細: plans/idproxy-m02-types.md

### M03: Config バリデーション
- [x] Config.Validate() 実装
- [x] デフォルト値適用ロジック
- [x] TDD: 正常系・異常系テスト
- 📄 詳細: plans/idproxy-m03-config-validation.md

### M04: MemoryStore - Session CRUD
- [x] MemoryStore 構造体・コンストラクタ
- [x] SetSession / GetSession / DeleteSession
- [x] TTL チェック（Get 時）
- [x] TDD: Session CRUD テスト
- 📄 詳細: plans/idproxy-m04-memstore-session.md

### M05: MemoryStore - AuthCode・AccessToken CRUD
- [x] SetAuthCode / GetAuthCode / DeleteAuthCode
- [x] SetAccessToken / GetAccessToken / DeleteAccessToken
- [x] TDD: AuthCode・AccessToken CRUD テスト
- 📄 詳細: plans/idproxy-m05-memstore-authcode-token.md

### M06: MemoryStore - クリーンアップ
- [x] Cleanup() 実装（期限切れエントリ削除）
- [x] バックグラウンド goroutine（time.Ticker 5分間隔）
- [x] Close() で Ticker 停止
- [x] TDD: クリーンアップテスト
- 📄 詳細: plans/idproxy-m06-memstore-cleanup.md

### M07: PKCE ユーティリティ ✅
- [x] S256 コードチャレンジ生成
- [x] コードチャレンジ検証（code_verifier → SHA256 → base64url 比較）
- [x] TDD: S256 生成・検証テスト（RFC 7636 テストベクター使用）
- 📄 詳細: plans/idproxy-m07-pkce.md

### M08: テストユーティリティ（モック IdP） ✅
- [x] testutil/mock_idp.go: テスト用 OIDC IdP サーバー
- [x] OIDC Discovery エンドポイント (.well-known/openid-configuration)
- [x] JWKS エンドポイント
- [x] Token エンドポイント（ID Token 発行）
- [x] Authorization エンドポイント（コールバックリダイレクト）
- 📄 詳細: plans/idproxy-m08-mock-idp.md

### M09: セッション管理 ✅
- [x] SessionManager 構造体
- [x] Cookie 暗号化（gorilla/securecookie）
- [x] セッション Cookie 発行・読み取り・削除
- [x] セッション有効期限管理
- [x] TDD: Cookie 暗号化・復号テスト、セッション CRUD テスト
- 📄 詳細: plans/idproxy-m09-session-manager.md

### M10: OIDC プロバイダー管理 ✅
- [x] ProviderManager 構造体
- [x] OIDC Discovery 取得・キャッシュ（go-oidc）
- [x] 複数 IdP 初期化・管理
- [x] プロバイダー選択ロジック（1つ→直接、複数→選択ページ）
- [x] プロバイダー選択 HTML ページ生成
- [x] TDD: モック IdP での初期化テスト
- 📄 詳細: plans/idproxy-m10-provider-manager.md（着手時に生成）

### M11: ブラウザ認証フロー
- [x] OIDC Authorization Request 生成（state, nonce）
- [x] IdP へのリダイレクト
- [x] /callback 処理（認可コード → ID Token 交換）
- [x] ID Token 検証（署名、issuer、audience、nonce、expiry）
- [x] AllowedDomains / AllowedEmails 認可判定
- [x] セッション作成・Cookie 発行・元 URL リダイレクト
- [x] TDD: モック IdP を使ったフルフローテスト
- 📄 詳細: plans/idproxy-m11-browser-auth-flow.md（着手時に生成）

### M12: Auth 構造体・Wrap()
- [ ] Auth 構造体、New() 関数
- [ ] Wrap(next http.Handler) http.Handler
- [ ] リクエスト判定ロジック（OAuth AS パス → OAuthServer / Bearer → JWT検証 / Cookie → セッション検証 / ブラウザ → リダイレクト / API → 401）
- [ ] 認証済みユーザー情報のコンテキスト注入
- [ ] TDD: 各分岐のリクエスト判定テスト
- 📄 詳細: plans/idproxy-m12-auth-wrap.md（着手時に生成）

### M13: Bearer Token 検証
- [ ] JWT 署名検証（ES256 公開鍵）
- [ ] クレーム検証（iss, exp, aud, email）
- [ ] Store でリボケーションチェック
- [ ] WWW-Authenticate ヘッダー付き 401 レスポンス
- [ ] TDD: 有効/無効/期限切れ JWT テスト
- 📄 詳細: plans/idproxy-m13-bearer-token.md（着手時に生成）

### M14: OAuth 2.1 メタデータ
- [ ] GET /.well-known/oauth-authorization-server
- [ ] RFC 8414 準拠レスポンス JSON
- [ ] PathPrefix 対応
- [ ] TDD: メタデータレスポンス検証テスト
- 📄 詳細: plans/idproxy-m14-oauth-metadata.md（着手時に生成）

### M15: OAuth 2.1 /authorize
- [ ] GET /authorize エンドポイント
- [ ] パラメータ検証（response_type, client_id, redirect_uri, code_challenge, code_challenge_method, state, scope）
- [ ] PKCE code_challenge 検証（S256 のみ）
- [ ] IdP 認証への委譲（ブラウザ認証フローと連携）
- [ ] TDD: 正常系・異常パラメータテスト
- 📄 詳細: plans/idproxy-m15-oauth-authorize.md（着手時に生成）

### M16: OAuth 2.1 /token
- [ ] POST /token エンドポイント
- [ ] grant_type=authorization_code 処理
- [ ] 認可コード取得・有効性検証
- [ ] PKCE 検証（SHA256(code_verifier) == code_challenge）
- [ ] Access Token（JWT ES256）署名・発行
- [ ] Store に AccessTokenData 保存
- [ ] 認可コード一回使用制約（二重使用時トークン無効化）
- [ ] TDD: トークン発行・PKCE検証・二重使用テスト
- 📄 詳細: plans/idproxy-m16-oauth-token.md（着手時に生成）

### M17: Dynamic Client Registration
- [ ] POST /register エンドポイント（RFC 7591）
- [ ] client_id 自動生成
- [ ] redirect_uris, client_name 等の登録
- [ ] クライアント情報の Store 保存
- [ ] TDD: 登録・取得テスト
- 📄 詳細: plans/idproxy-m17-dcr.md（着手時に生成）

### M18: スタンドアロンプロキシ・SSE パススルー
- [ ] cmd/idproxy/main.go エントリポイント
- [ ] 環境変数パース → Config 構築
- [ ] httputil.ReverseProxy + FlushInterval:-1
- [ ] SSE ストリーミングパススルー
- [ ] ヘルスチェック（/healthz）
- [ ] グレースフルシャットダウン
- [ ] TDD: 環境変数パーステスト、SSE パススルーテスト
- 📄 詳細: plans/idproxy-m18-standalone-proxy.md（着手時に生成）

### M19: 統合テスト
- [ ] ブラウザ認証フロー E2E（モック IdP → Cookie → upstream）
- [ ] OAuth 2.1 フロー E2E（メタデータ → authorize → token → Bearer → upstream）
- [ ] DCR → OAuth 2.1 フロー E2E
- [ ] SSE パススルー E2E（認証付き SSE 接続）
- [ ] 複数 IdP 同時テスト
- 📄 詳細: plans/idproxy-m19-integration-tests.md（着手時に生成）

### M20: ドキュメント・CI/CD・リリース
- [ ] README.md（概要、クイックスタート、設定一覧）
- [ ] examples/basic/main.go
- [ ] examples/mcp-server/main.go
- [ ] .goreleaser.yml
- [ ] .github/workflows/ci.yml（テスト、lint、ビルド）
- [ ] .github/workflows/release.yml（tag → GoReleaser）
- 📄 詳細: plans/idproxy-m20-docs-cicd.md（着手時に生成）

## Blockers
なし

## Architecture Decisions
| # | 決定 | 理由 | 日付 |
|---|------|------|------|
| 1 | MIT ライセンス | Go OSS の慣例、シンプル | 2026-04-08 |
| 2 | 未設定時は全員許可 | OIDC 認証通過で十分、直感的 | 2026-04-08 |
| 3 | ES256 デフォルト | 鍵サイズ小・高速、OAuth 2.1 推奨 | 2026-04-08 |
| 4 | DCR を MVP に含める | Claude Cowork 互換に必須 | 2026-04-08 |
| 5 | http.Handler ミドルウェアパターン | Go 標準パターン、mcp-go 互換 | 2026-04-08 |
| 6 | Cookie + encrypted JWT セッション | ステートレス、securecookie 実績 | 2026-04-08 |
| 7 | Store インターフェースで永続化抽象化 | 環境に応じた差し替え、MVP はインメモリ | 2026-04-08 |

## Changelog
| 日時 | 種別 | 内容 |
|------|------|------|
| 2026-04-08 17:10 | 作成 | ロードマップ初版作成（20マイルストーン）。スペックの Open Questions を解決し、TDD 方針で細粒度に分割 |
