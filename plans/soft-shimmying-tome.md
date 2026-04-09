# Plan: README英語化 + CLI help修正 + MCP E2Eテストサーバー

## Context

idproxy は公開 OSS プロジェクトだが、README・コードコメント・CLI 出力がすべて日本語。国際的な利用を想定し英語を基本言語にする。また CLI の `-h` フラグが環境変数未設定時にエラーで終了する問題を修正し、E2E テスト用の小さな MCP サーバーを追加する。

---

## Task 1: コードコメント英語化 (main.go / config.go)

Task 2 と同じファイルを触るため先に実施。

### 対象ファイル
- `cmd/idproxy/main.go` — 7箇所の日本語コメントを英語に
- `cmd/idproxy/config.go` — 14箇所の日本語コメントを英語に

### 主な変換
| 行 | 日本語 | 英語 |
|---|---|---|
| main.go:34 | `// Auth の初期化` | `// Initialize Auth` |
| main.go:41 | `// リバースプロキシの設定` | `// Configure reverse proxy` |
| main.go:47 | `// ルーティング` | `// Set up routing` |
| main.go:57 | `// グレースフルシャットダウン` | `// Graceful shutdown` |
| main.go:77-78 | godoc コメント | English godoc |
| main.go:86 | SSE コメント | English |
| main.go:91 | godoc コメント | English godoc |
| config.go:13-14 | godoc コメント | English godoc |
| config.go:19-56 | 各環境変数コメント | `// VAR_NAME (required)` 形式 |
| config.go:87-108 | オプション変数コメント | English |
| config.go:122-123 | splitTrim godoc | English godoc |

### 検証
```bash
go vet ./cmd/idproxy/...
go test ./cmd/idproxy/...
```

---

## Task 2: CLI `-h` フラグ修正

### 問題
`go run ./cmd/idproxy/... -h` で `parseConfig()` が先に走り、環境変数バリデーションエラーが出る。

### 解決策
`flag` パッケージを導入し、`flag.Parse()` を `parseConfig()` の前に呼ぶ。

### 対象ファイル
- `cmd/idproxy/main.go` — `run()` に `flag.Usage = printUsage; flag.Parse()` を追加
- `cmd/idproxy/config.go` — `printUsage()` 関数を追加
- `cmd/idproxy/main_test.go` — `TestPrintUsage` を追加

### main.go 変更

```go
import "flag"

func run() error {
    flag.Usage = printUsage
    flag.Parse()

    cfg, upstream, listenAddr, err := parseConfig()
    // ... rest unchanged
}
```

### config.go に追加する `printUsage()`

```go
func printUsage() {
    w := flag.CommandLine.Output()
    fmt.Fprintf(w, "Usage: idproxy [options]\n\n")
    fmt.Fprintf(w, "OIDC authentication reverse proxy and MCP OAuth 2.1 Authorization Server.\n\n")
    fmt.Fprintf(w, "Environment Variables:\n\n")
    fmt.Fprintf(w, "  Required:\n")
    fmt.Fprintf(w, "    UPSTREAM_URL          Backend URL to proxy to\n")
    fmt.Fprintf(w, "    EXTERNAL_URL          External URL of this service\n")
    fmt.Fprintf(w, "    COOKIE_SECRET         Cookie encryption key (hex-encoded, 32+ bytes)\n")
    fmt.Fprintf(w, "    OIDC_ISSUER           OIDC Issuer URL (comma-separated for multiple)\n")
    fmt.Fprintf(w, "    OIDC_CLIENT_ID        OAuth Client ID (comma-separated for multiple)\n\n")
    fmt.Fprintf(w, "  Optional:\n")
    fmt.Fprintf(w, "    OIDC_CLIENT_SECRET    OAuth Client Secret (comma-separated for multiple)\n")
    fmt.Fprintf(w, "    OIDC_PROVIDER_NAME    Provider display name (comma-separated for multiple)\n")
    fmt.Fprintf(w, "    ALLOWED_DOMAINS       Allowed email domains (comma-separated)\n")
    fmt.Fprintf(w, "    ALLOWED_EMAILS        Allowed email addresses (comma-separated)\n")
    fmt.Fprintf(w, "    PATH_PREFIX           OAuth 2.1 AS endpoint path prefix\n")
    fmt.Fprintf(w, "    PORT                  Listen port (default: 8080)\n")
}
```

### 動作
Go の `flag` は `-h` を受けると `flag.Usage()` を呼んで `os.Exit(2)` する。これは Go の標準的な挙動。

### 検証
```bash
go run ./cmd/idproxy/... -h   # ヘルプが表示され exit 2
go run ./cmd/idproxy/... --help  # 同上
go test ./cmd/idproxy/...
```

---

## Task 3: README 英語化 + 日本語版作成

### 対象ファイル
- `README.md` — 現在の日本語を英語に全面書き換え
- `README_ja.md` — 新規作成、現在の日本語 README をコピー

### 構造
両ファイルの先頭に言語切替リンクを配置:

**README.md:**
```markdown
**English** | [日本語](README_ja.md)

# idproxy
...
```

**README_ja.md:**
```markdown
[English](README.md) | **日本語**

# idproxy
...
```

### 翻訳対象セクション
- 見出し・説明文を英語化
- 環境変数テーブルのヘッダー・説明セルを英語化
- コードブロック内の日本語コメントを英語化
- コード自体 (変数名、import 等) はそのまま

### 検証
目視確認。リンクの相互参照が正しいことを確認。

---

## Task 4: MCP テストサーバー + E2E テスト

### 目的
testutil に小さな MCP サーバーを追加し、idproxy 越しの MCP フルフロー E2E テストを可能にする。

### 新規ファイル
- `testutil/mock_mcp.go` — Mock MCP サーバー (JSON-RPC 2.0 over SSE)
- `testutil/mock_mcp_test.go` — Mock MCP 単体テスト

### 修正ファイル
- `integration_test.go` — MCP E2E テストシナリオ追加

### MockMCP 設計

`mock_idp.go` と同パターン: struct + `NewMockMCP(t testing.TB)` + `t.Cleanup` で自動終了。

```go
type MockMCP struct {
    Server    *httptest.Server
    mu        sync.Mutex
    sessions  map[string]chan jsonRPCResponse
    toolCalls []ToolCallRecord
}

type ToolCallRecord struct {
    Name      string
    Arguments map[string]any
}
```

### MCP プロトコルエンドポイント

| Method | Path | 動作 |
|--------|------|------|
| GET | `/sse` | SSE 接続。`event: endpoint` でメッセージ送信先 URL を返す |
| POST | `/message?session_id=<id>` | JSON-RPC 2.0 リクエスト受信、SSE で応答返却 |

### JSON-RPC メソッド

| Method | 応答 |
|--------|------|
| `initialize` | サーバー情報 + capabilities (tools サポート) |
| `notifications/initialized` | 通知 — 応答なし |
| `tools/list` | echo ツール 1 つ |
| `tools/call` (echo) | 入力メッセージをそのまま返す |

### echo ツール定義

```go
var echoTool = map[string]any{
    "name":        "echo",
    "description": "Echoes back the input message",
    "inputSchema": map[string]any{
        "type": "object",
        "properties": map[string]any{
            "message": map[string]any{
                "type":        "string",
                "description": "Message to echo back",
            },
        },
        "required": []string{"message"},
    },
}
```

### セッション ID 生成
`crypto/rand` + `encoding/hex` で生成（既存 mock_idp.go と同パターン、外部依存追加なし）。

### mock_mcp_test.go テストケース
1. `TestMockMCP_SSEEndpoint` — `/sse` 接続、`endpoint` イベント受信
2. `TestMockMCP_Initialize` — `initialize` リクエスト → capabilities 応答
3. `TestMockMCP_ToolsList` — `tools/list` → echo ツール返却
4. `TestMockMCP_ToolsCall` — `tools/call` echo → メッセージ返却
5. `TestMockMCP_InvalidMethod` — 不明メソッド → JSON-RPC エラー

### E2E テストシナリオ (integration_test.go)

`TestIntegration_MCPOAuthFullFlow`:

1. `MockMCP` + `MockIdP` 起動
2. idproxy を `setupAuth()` で起動（MockMCP を upstream に）
3. `GET /.well-known/oauth-authorization-server` — メタデータ取得
4. `POST /register` — Dynamic Client Registration
5. MockIdP 経由でブラウザログイン → セッション Cookie 取得
6. `GET /authorize` with PKCE → 認可コード取得
7. `POST /token` with code + code_verifier → Bearer トークン取得
8. `GET /sse` with `Authorization: Bearer <token>` → SSE 接続、`endpoint` イベント受信
9. `POST /message` with Bearer トークン → `initialize` 送信
10. SSE ストリームで `initialize` 応答受信
11. `tools/list` → echo ツール確認
12. `tools/call` echo → 結果確認

### 検証
```bash
go test ./testutil/...                    # mock_mcp 単体テスト
go test -tags integration ./...           # E2E テスト含む全テスト
```

---

## 実装順序

1. **Task 1**: コメント英語化 (main.go, config.go)
2. **Task 2**: CLI `-h` 修正 (同じファイルの追加変更)
3. **Task 3**: README 英語化 + README_ja.md 作成
4. **Task 4**: MockMCP + E2E テスト

Task 1-2 は同じファイルを触るため順序固定。Task 3-4 は独立しており並列実行可能。
