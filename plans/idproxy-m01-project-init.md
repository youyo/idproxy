# M01: プロジェクト初期化

## Overview
| 項目 | 値 |
|------|---|
| ステータス | 未着手 |
| 依存 | なし（最初のマイルストーン） |
| 対象ファイル | go.mod, LICENSE, .gitignore, ディレクトリ構造 |

## Goal
Go モジュールとリポジトリの基盤を整備し、後続マイルストーンの開発を開始できる状態にする。

## Implementation Steps

- [ ] Step 1: `go mod init github.com/youyo/idproxy`（Go 1.26）
- [ ] Step 2: 依存ライブラリの追加
  - `github.com/coreos/go-oidc/v3` — OIDC Discovery, ID Token 検証
  - `golang.org/x/oauth2` — OAuth2 Authorization Code Flow
  - `github.com/golang-jwt/jwt/v5` — JWT 署名・検証
  - `github.com/gorilla/securecookie` — Cookie 暗号化
  - `github.com/google/uuid` — UUID 生成
- [ ] Step 3: ディレクトリ構造作成
  ```
  store/          # Store 実装
  cmd/idproxy/    # スタンドアロンバイナリ
  testutil/       # テストヘルパー
  examples/       # 使用例
    basic/
    mcp-server/
  ```
- [ ] Step 4: MIT LICENSE ファイル作成
- [ ] Step 5: .gitignore 作成（Go 標準 + バイナリ）
- [ ] Step 6: 空の placeholder ファイル作成（各パッケージの doc.go）
  - `doc.go` — パッケージドキュメント
  - `store/doc.go`
  - `cmd/idproxy/main.go` — 空の main 関数
- [ ] Step 7: `go mod tidy` で依存解決を確認
- [ ] Step 8: ビルド確認（`go build ./...` が成功すること）

## TDD Test Design
このマイルストーンは基盤構築のため、テスト対象のロジックはなし。
次の M02（基本型定義）から TDD サイクルを開始する。

## Verification
- `go build ./...` がエラーなく完了
- `go vet ./...` が警告なし
- ディレクトリ構造がスペック Section 11 と一致
- go.mod に全依存ライブラリが含まれている

## Risks
| リスク | 影響度 | 対策 |
|--------|--------|------|
| Go 1.26 が未リリースの場合 | 中 | Go 1.24 で開始し、go.mod の go directive のみ変更 |
| 依存ライブラリのバージョン衝突 | 低 | go mod tidy で自動解決、問題なければ最新を使用 |
