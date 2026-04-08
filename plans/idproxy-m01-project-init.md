# M01: プロジェクト初期化

## Overview
| 項目 | 値 |
|------|---|
| ステータス | 完了 |
| 依存 | なし（最初のマイルストーン） |
| 対象ファイル | go.mod, go.sum, LICENSE, .gitignore, ディレクトリ構造, doc.go, main.go |
| 見積もり | 30分 |

## Goal
Go モジュールとリポジトリの基盤を整備し、後続マイルストーン（M02: 基本型定義）の開発を開始できる状態にする。
`go build ./...` と `go vet ./...` がエラーなしで通ることが完了条件。

## Architecture Decisions
| # | 決定 | 理由 |
|---|------|------|
| 1 | Go 1.26 を使用（go directive） | mise.toml で Go 1.26 指定済み、go1.26.1 インストール確認済み |
| 2 | MIT ライセンス | ロードマップの Design Decisions #1 に準拠 |
| 3 | ルートパッケージは `idproxy` | `go get github.com/youyo/idproxy` でライブラリとして使用可能にする |
| 4 | 各サブパッケージに doc.go を配置 | パッケージの存在を go tools に認識させるため |

## Implementation Steps

### Step 1: Go モジュール初期化
```bash
go mod init github.com/youyo/idproxy
```
- go.mod の go directive は 1.26（mise.toml 準拠、go1.26.1 確認済み）

### Step 2: ディレクトリ構造作成
スペック Section 11 に準拠:
```
idproxy/
├── go.mod
├── go.sum
├── LICENSE
├── .gitignore
├── doc.go                  # ルートパッケージドキュメント
├── store/
│   └── doc.go              # store パッケージドキュメント
├── cmd/
│   └── idproxy/
│       └── main.go         # 空の main 関数
├── testutil/
│   └── doc.go              # testutil パッケージドキュメント
└── examples/
    ├── basic/
    │   └── main.go         # placeholder
    └── mcp-server/
        └── main.go         # placeholder
```

### Step 3: MIT LICENSE ファイル作成
- 著作権者: youyo
- 年: 2026

### Step 4: .gitignore 作成
- Go 標準パターン（バイナリ、テストカバレッジ、IDE 設定）
- `cmd/idproxy/idproxy` バイナリ

### Step 5: doc.go ファイル作成
各パッケージの目的を簡潔に記述:
- `doc.go`: idproxy パッケージの概要（OIDC 認証 + MCP OAuth 2.1 AS ミドルウェア）
- `store/doc.go`: Store インターフェースの実装パッケージ
- `testutil/doc.go`: テストヘルパー（モック IdP 等）

### Step 6: cmd/idproxy/main.go 作成
```go
package main

func main() {
    // TODO: M18 で実装
}
```

### Step 7: examples placeholder 作成
- `examples/basic/main.go`: 空の main 関数 + TODO コメント
- `examples/mcp-server/main.go`: 空の main 関数 + TODO コメント

### Step 8: go mod tidy
```bash
go mod tidy
```
M01 では外部依存ライブラリは追加しない。依存は M02 以降で実際に使用するタイミングで追加する。

### Step 9: ビルド・検証
```bash
go build ./...
go vet ./...
```

## TDD Test Design

M01 はプロジェクト基盤構築のため、テスト対象のビジネスロジックはなし。
TDD サイクルは M02（基本型定義）から開始する。

### 最小検証テスト
ビルドが通ることを確認するための最小テスト:
```go
// idproxy_test.go
package idproxy_test

import "testing"

func TestPackageExists(t *testing.T) {
    // M01: パッケージが正しくインポートできることを確認
    // 実質的なテストは M02 以降で追加
}
```

## Verification Checklist
- [ ] `go build ./...` がエラーなく完了
- [ ] `go vet ./...` が警告なし
- [ ] `go test ./...` が成功
- [ ] ディレクトリ構造がスペック Section 11 と一致（M01 対象分）
- [ ] LICENSE ファイルが MIT ライセンス
- [ ] .gitignore が Go 標準パターンを含む
- [ ] 各パッケージの doc.go が存在
- [ ] go.sum が正しく生成されている（依存なしの場合は存在しなくてもOK）

## Sequence Diagram

```
Developer                    Go Toolchain
    |                              |
    |-- go mod init -------------->|
    |<--- go.mod created ---------|
    |                              |
    |-- mkdir -p (dirs) ---------> | (filesystem)
    |-- create doc.go files -----> | (filesystem)
    |-- create LICENSE ----------> | (filesystem)
    |-- create .gitignore -------> | (filesystem)
    |                              |
    |-- go build ./... ----------->|
    |<--- BUILD SUCCESS ----------|
    |                              |
    |-- go vet ./... ------------->|
    |<--- NO WARNINGS ------------|
    |                              |
    |-- go test ./... ------------>|
    |<--- PASS -------------------|
    |                              |
    |-- git add & commit --------->| (git)
```

## Risks
| リスク | 影響度 | 確率 | 対策 |
|--------|--------|------|------|
| Go 1.26 が未リリース | — | — | 解消済み: go1.26.1 インストール確認済み |
| go mod tidy で依存が消える | — | — | 解消済み: M01 では外部依存を追加しない方針に統一 |
| ディレクトリ構造の不一致 | 低 | 低 | スペック Section 11 を明示的に参照して作成 |
| examples/ が go build でエラー | 低 | 中 | 空の main 関数のみ配置、import なし |

## Dependencies on Next Milestone
M02（基本型定義）が本マイルストーンの成果物に依存:
- go.mod が存在すること
- ルートパッケージ `idproxy` が存在すること
- `store/` パッケージが存在すること

## Handoff to M02
- go.mod の module path: `github.com/youyo/idproxy`
- Go version: 1.26（go directive）
- ライセンス: MIT
- ディレクトリ構造は完成済み、型定義・Store インターフェースの追加が可能
