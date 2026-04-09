package testutil

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// jsonRPCRequest は JSON-RPC 2.0 リクエストを表す。
type jsonRPCRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      any            `json:"id,omitempty"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params,omitempty"`
}

// jsonRPCResponse は JSON-RPC 2.0 レスポンスを表す。
type jsonRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id,omitempty"`
	Result  any           `json:"result,omitempty"`
	Error   *jsonRPCError `json:"error,omitempty"`
}

// jsonRPCError は JSON-RPC 2.0 エラーオブジェクトを表す。
type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ToolCallRecord は tools/call の呼び出し記録を保持する。
type ToolCallRecord struct {
	Name      string
	Arguments map[string]any
}

// mcpSession は SSE 接続セッションを表す。
type mcpSession struct {
	ch chan jsonRPCResponse
}

// echoTool は echo ツールの定義。
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

// MockMCP はテスト用の MCP サーバーを表す。
// JSON-RPC 2.0 over SSE トランスポートを実装する。
type MockMCP struct {
	server    *httptest.Server
	mu        sync.Mutex
	sessions  map[string]*mcpSession
	toolCalls []ToolCallRecord
}

// NewMockMCP はテスト用 MCP サーバーを起動し、MockMCP を返す。
// t.Cleanup でサーバーが自動クローズされる。
func NewMockMCP(t testing.TB) *MockMCP {
	t.Helper()

	m := &MockMCP{
		sessions: make(map[string]*mcpSession),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/sse", m.handleSSE)
	mux.HandleFunc("/message", m.handleMessage)

	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)

	return m
}

// URL はサーバーのベース URL を返す。
func (m *MockMCP) URL() string {
	return m.server.URL
}

// ToolCalls は記録されたツール呼び出しのコピーを返す。
func (m *MockMCP) ToolCalls() []ToolCallRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]ToolCallRecord, len(m.toolCalls))
	copy(result, m.toolCalls)
	return result
}

// handleSSE は GET /sse を処理する。
// SSE 接続を確立し、セッション ID を生成してエンドポイント情報を送信する。
func (m *MockMCP) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// セッション ID を生成
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		http.Error(w, "failed to generate session ID", http.StatusInternalServerError)
		return
	}
	sessionID := hex.EncodeToString(idBytes)

	// セッションを登録
	sess := &mcpSession{
		ch: make(chan jsonRPCResponse, 10),
	}
	m.mu.Lock()
	m.sessions[sessionID] = sess
	m.mu.Unlock()

	// SSE ヘッダーを設定
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// エンドポイント情報を送信
	fmt.Fprintf(w, "event: endpoint\ndata: /message?session_id=%s\n\n", sessionID)
	flusher.Flush()

	// コンテキストがキャンセルされるまでレスポンスを送信
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			// クライアント切断
			m.mu.Lock()
			delete(m.sessions, sessionID)
			m.mu.Unlock()
			return
		case resp := <-sess.ch:
			data, err := json.Marshal(resp)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(data))
			flusher.Flush()
		}
	}
}

// handleMessage は POST /message?session_id=<id> を処理する。
// JSON-RPC 2.0 リクエストを受け取り、セッションの SSE チャネルにレスポンスを送信する。
func (m *MockMCP) handleMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	sess, ok := m.sessions[sessionID]
	m.mu.Unlock()
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	var req jsonRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// メソッドに応じたレスポンスを生成
	resp := m.handleMethod(req)

	// レスポンスがある場合、セッションの SSE チャネルに送信
	if resp != nil {
		select {
		case sess.ch <- *resp:
		default:
			// チャネルがフルの場合はドロップ
		}
	}

	// 202 Accepted を即座に返す
	w.WriteHeader(http.StatusAccepted)
}

// handleMethod は JSON-RPC メソッドに応じたレスポンスを生成する。
// notification（レスポンス不要）の場合は nil を返す。
func (m *MockMCP) handleMethod(req jsonRPCRequest) *jsonRPCResponse {
	switch req.Method {
	case "initialize":
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":   map[string]any{"tools": map[string]any{}},
				"serverInfo": map[string]any{
					"name":    "mock-mcp",
					"version": "0.1.0",
				},
			},
		}

	case "notifications/initialized":
		// notification: レスポンス不要
		return nil

	case "ping":
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]any{},
		}

	case "tools/list":
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": []any{echoTool},
			},
		}

	case "tools/call":
		return m.handleToolsCall(req)

	default:
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &jsonRPCError{
				Code:    -32601,
				Message: "method not found",
			},
		}
	}
}

// handleToolsCall は tools/call メソッドを処理する。
func (m *MockMCP) handleToolsCall(req jsonRPCRequest) *jsonRPCResponse {
	name, _ := req.Params["name"].(string)
	arguments, _ := req.Params["arguments"].(map[string]any)

	// ツール呼び出しを記録
	m.mu.Lock()
	m.toolCalls = append(m.toolCalls, ToolCallRecord{
		Name:      name,
		Arguments: arguments,
	})
	m.mu.Unlock()

	if name == "echo" {
		message, _ := arguments["message"].(string)
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"content": []any{
					map[string]any{
						"type": "text",
						"text": "echo: " + message,
					},
				},
				"isError": false,
			},
		}
	}

	return &jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Error: &jsonRPCError{
			Code:    -32601,
			Message: "method not found",
		},
	}
}
