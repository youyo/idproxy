package testutil_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/youyo/idproxy/testutil"
)

// sseEvent は SSE イベントを表す。
type sseEvent struct {
	Event string
	Data  string
}

// readSSEEvent は bufio.Scanner から次の SSE イベントを読み取る。
// タイムアウト付きコンテキストで使用すること。
func readSSEEvent(scanner *bufio.Scanner) *sseEvent {
	var event sseEvent
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// 空行はイベントの区切り
			if event.Event != "" || event.Data != "" {
				return &event
			}
			continue
		}
		if strings.HasPrefix(line, "event: ") {
			event.Event = strings.TrimPrefix(line, "event: ")
		} else if strings.HasPrefix(line, "data: ") {
			event.Data = strings.TrimPrefix(line, "data: ")
		}
	}
	if event.Event != "" || event.Data != "" {
		return &event
	}
	return nil
}

// connectSSE は MockMCP の /sse に接続し、endpoint イベントからメッセージ URL を取得する。
// 返り値: メッセージエンドポイントの完全 URL, SSE レスポンスボディの Scanner, レスポンス, エラー
func connectSSE(t *testing.T, mcpURL string) (string, *bufio.Scanner, *http.Response) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	req, err := http.NewRequestWithContext(ctx, "GET", mcpURL+"/sse", nil)
	if err != nil {
		t.Fatalf("failed to create SSE request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to connect SSE: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		t.Fatalf("expected 200 for /sse, got %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)

	// endpoint イベントを読み取り
	ev := readSSEEvent(scanner)
	if ev == nil {
		_ = resp.Body.Close()
		t.Fatal("no SSE event received")
	}
	if ev.Event != "endpoint" {
		_ = resp.Body.Close()
		t.Fatalf("expected event=endpoint, got %s", ev.Event)
	}

	// data からメッセージ URL を構築
	messageURL := mcpURL + ev.Data

	return messageURL, scanner, resp
}

// postJSONRPC は JSON-RPC 2.0 リクエストを POST する。
func postJSONRPC(t *testing.T, url string, id any, method string, params map[string]any) {
	t.Helper()

	body := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
	}
	if id != nil {
		body["id"] = id
	}
	if params != nil {
		body["params"] = params
	}

	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("failed to marshal JSON-RPC request: %v", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("failed to POST message: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d", resp.StatusCode)
	}
}

// TestMockMCP_SSEEndpoint は /sse に接続して endpoint イベントを受信できることを確認する。
func TestMockMCP_SSEEndpoint(t *testing.T) {
	mcp := testutil.NewMockMCP(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", mcp.URL()+"/sse", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("expected Content-Type=text/event-stream, got %s", ct)
	}

	scanner := bufio.NewScanner(resp.Body)
	ev := readSSEEvent(scanner)
	if ev == nil {
		t.Fatal("no SSE event received")
	}

	if ev.Event != "endpoint" {
		t.Fatalf("expected event=endpoint, got %s", ev.Event)
	}
	if !strings.Contains(ev.Data, "/message?session_id=") {
		t.Fatalf("expected data to contain /message?session_id=, got %s", ev.Data)
	}
}

// TestMockMCP_Initialize は initialize メソッドが protocolVersion を返すことを確認する。
func TestMockMCP_Initialize(t *testing.T) {
	mcp := testutil.NewMockMCP(t)

	messageURL, scanner, resp := connectSSE(t, mcp.URL())
	defer func() { _ = resp.Body.Close() }()

	postJSONRPC(t, messageURL, 1, "initialize", map[string]any{})

	ev := readSSEEvent(scanner)
	if ev == nil {
		t.Fatal("no SSE response received for initialize")
	}
	if ev.Event != "message" {
		t.Fatalf("expected event=message, got %s", ev.Event)
	}

	var rpcResp map[string]any
	if err := json.Unmarshal([]byte(ev.Data), &rpcResp); err != nil {
		t.Fatalf("failed to unmarshal SSE response: %v", err)
	}

	result, ok := rpcResp["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result object, got %v", rpcResp["result"])
	}

	if result["protocolVersion"] != "2024-11-05" {
		t.Fatalf("expected protocolVersion=2024-11-05, got %v", result["protocolVersion"])
	}

	serverInfo, ok := result["serverInfo"].(map[string]any)
	if !ok {
		t.Fatal("expected serverInfo in result")
	}
	if serverInfo["name"] != "mock-mcp" {
		t.Fatalf("expected serverInfo.name=mock-mcp, got %v", serverInfo["name"])
	}
}

// TestMockMCP_ToolsList は tools/list メソッドが echo ツールを返すことを確認する。
func TestMockMCP_ToolsList(t *testing.T) {
	mcp := testutil.NewMockMCP(t)

	messageURL, scanner, resp := connectSSE(t, mcp.URL())
	defer func() { _ = resp.Body.Close() }()

	postJSONRPC(t, messageURL, 2, "tools/list", nil)

	ev := readSSEEvent(scanner)
	if ev == nil {
		t.Fatal("no SSE response received for tools/list")
	}

	var rpcResp map[string]any
	if err := json.Unmarshal([]byte(ev.Data), &rpcResp); err != nil {
		t.Fatalf("failed to unmarshal SSE response: %v", err)
	}

	result, ok := rpcResp["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result object, got %v", rpcResp["result"])
	}

	tools, ok := result["tools"].([]any)
	if !ok || len(tools) == 0 {
		t.Fatalf("expected non-empty tools array, got %v", result["tools"])
	}

	tool, ok := tools[0].(map[string]any)
	if !ok {
		t.Fatalf("expected tool object, got %v", tools[0])
	}

	if tool["name"] != "echo" {
		t.Fatalf("expected tool name=echo, got %v", tool["name"])
	}
}

// TestMockMCP_ToolsCall は tools/call メソッドで echo ツールが呼び出せることを確認する。
func TestMockMCP_ToolsCall(t *testing.T) {
	mcp := testutil.NewMockMCP(t)

	messageURL, scanner, resp := connectSSE(t, mcp.URL())
	defer func() { _ = resp.Body.Close() }()

	postJSONRPC(t, messageURL, 3, "tools/call", map[string]any{
		"name":      "echo",
		"arguments": map[string]any{"message": "hello"},
	})

	ev := readSSEEvent(scanner)
	if ev == nil {
		t.Fatal("no SSE response received for tools/call")
	}

	var rpcResp map[string]any
	if err := json.Unmarshal([]byte(ev.Data), &rpcResp); err != nil {
		t.Fatalf("failed to unmarshal SSE response: %v", err)
	}

	result, ok := rpcResp["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result object, got %v", rpcResp["result"])
	}

	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatal("expected non-empty content array")
	}

	item, ok := content[0].(map[string]any)
	if !ok {
		t.Fatalf("expected content item object, got %v", content[0])
	}

	if item["text"] != "echo: hello" {
		t.Fatalf("expected text='echo: hello', got %v", item["text"])
	}

	// ToolCalls() の記録を確認
	calls := mcp.ToolCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(calls))
	}
	if calls[0].Name != "echo" {
		t.Fatalf("expected tool name=echo, got %s", calls[0].Name)
	}
	if calls[0].Arguments["message"] != "hello" {
		t.Fatalf("expected argument message=hello, got %v", calls[0].Arguments["message"])
	}
}

// TestMockMCP_InvalidMethod は不明メソッドで JSON-RPC エラーが返ることを確認する。
func TestMockMCP_InvalidMethod(t *testing.T) {
	mcp := testutil.NewMockMCP(t)

	messageURL, scanner, resp := connectSSE(t, mcp.URL())
	defer func() { _ = resp.Body.Close() }()

	postJSONRPC(t, messageURL, 4, "nonexistent/method", nil)

	ev := readSSEEvent(scanner)
	if ev == nil {
		t.Fatal("no SSE response received for invalid method")
	}

	var rpcResp map[string]any
	if err := json.Unmarshal([]byte(ev.Data), &rpcResp); err != nil {
		t.Fatalf("failed to unmarshal SSE response: %v", err)
	}

	errObj, ok := rpcResp["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", rpcResp["error"])
	}

	code, ok := errObj["code"].(float64)
	if !ok || int(code) != -32601 {
		t.Fatalf("expected error code=-32601, got %v", errObj["code"])
	}

	msg, ok := errObj["message"].(string)
	if !ok || msg != "method not found" {
		t.Fatalf("expected error message='method not found', got %v", errObj["message"])
	}
}
