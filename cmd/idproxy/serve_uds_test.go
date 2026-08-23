package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// newUnixListener は UDS リスナーを作る。sun_path の 108 バイト制限を避けるため
// t.TempDir() ではなく os.MkdirTemp の短いパスを使う。
// AF_UNIX の bind を禁じたサンドボックスでは EPERM になるためスキップする
// （CI の ubuntu-latest では bind できるので実行される）。それ以外のエラーは失敗扱い。
func newUnixListener(t testing.TB) (net.Listener, string) {
	t.Helper()

	dir, err := os.MkdirTemp("", "idpx")
	if err != nil {
		t.Fatalf("MkdirTemp() error: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	socketPath := filepath.Join(dir, "u.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		if isBindNotPermitted(err) {
			t.Skipf("AF_UNIX bind is not permitted in this environment: %v", err)
		}
		t.Fatalf("net.Listen(unix, %q) error: %v", socketPath, err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	return ln, socketPath
}

func isBindNotPermitted(err error) bool {
	return errors.Is(err, syscall.EPERM) || strings.Contains(err.Error(), "operation not permitted")
}

// newUnixUpstream は h を UDS 上で提供する upstream を起動し、ソケットパスを返す。
func newUnixUpstream(t testing.TB, h http.Handler) string {
	t.Helper()

	ln, socketPath := newUnixListener(t)
	srv := httptest.NewUnstartedServer(h)
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)

	return socketPath
}

func TestParseUpstream_UnixScheme(t *testing.T) {
	target, socketPath, err := parseUpstream("unix:///var/run/backend.sock")
	if err != nil {
		t.Fatalf("parseUpstream() error: %v", err)
	}
	if got, want := target.String(), "http://unix"; got != want {
		t.Errorf("target = %q, want %q", got, want)
	}
	if got, want := socketPath, "/var/run/backend.sock"; got != want {
		t.Errorf("socketPath = %q, want %q", got, want)
	}
}

func TestParseUpstream_TCPSchemesUnchanged(t *testing.T) {
	for _, raw := range []string{"http://localhost:3000", "https://backend.example.com/base"} {
		target, socketPath, err := parseUpstream(raw)
		if err != nil {
			t.Fatalf("parseUpstream(%q) error: %v", raw, err)
		}
		if target.String() != raw {
			t.Errorf("target = %q, want %q", target.String(), raw)
		}
		if socketPath != "" {
			t.Errorf("socketPath = %q, want empty for %q", socketPath, raw)
		}
	}
}

func TestParseUpstream_UnixInvalid(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"path missing", "unix://"},
		{"relative path", "unix://relative/backend.sock"},
		{"dot relative path", "unix://./backend.sock"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := parseUpstream(tt.raw); err == nil {
				t.Fatalf("parseUpstream(%q) expected error", tt.raw)
			}
		})
	}
}

func TestNewReverseProxy_UnixInvalidSocketPath(t *testing.T) {
	if _, err := newReverseProxy("unix://relative/backend.sock", ""); err == nil {
		t.Fatal("expected error for unix:// URL without an absolute socket path")
	}
}

// TestNewReverseProxy_UnixDialsSocketPath は bind を伴わずに Transport の構成を検証する。
// 存在しないソケットへの dial エラーがソケットパスを含むことで、addr ではなく
// UDS 側へ接続していることを確かめる。
func TestNewReverseProxy_UnixDialsSocketPath(t *testing.T) {
	const socketPath = "/nonexistent-idproxy-test/backend.sock"

	proxy, err := newReverseProxy("unix://"+socketPath, "")
	if err != nil {
		t.Fatalf("newReverseProxy() error: %v", err)
	}
	transport, ok := proxy.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("proxy.Transport = %T, want *http.Transport", proxy.Transport)
	}
	if transport.DialContext == nil {
		t.Fatal("transport.DialContext is nil")
	}

	// 既定 Transport の Clone であること（タイムアウト・コネクション上限を落とさない）。
	def := http.DefaultTransport.(*http.Transport)
	if transport.MaxIdleConns != def.MaxIdleConns {
		t.Errorf("MaxIdleConns = %d, want %d", transport.MaxIdleConns, def.MaxIdleConns)
	}
	if transport.IdleConnTimeout != def.IdleConnTimeout {
		t.Errorf("IdleConnTimeout = %v, want %v", transport.IdleConnTimeout, def.IdleConnTimeout)
	}

	_, err = transport.DialContext(context.Background(), "tcp", "unix:80")
	if err == nil {
		t.Fatal("expected dial error for a nonexistent socket")
	}
	if !strings.Contains(err.Error(), socketPath) {
		t.Errorf("dial error = %v, want it to mention socket path %q", err, socketPath)
	}
}

func TestNewReverseProxy_TCPKeepsDefaultTransport(t *testing.T) {
	proxy, err := newReverseProxy("http://localhost:3000", "")
	if err != nil {
		t.Fatalf("newReverseProxy() error: %v", err)
	}
	if proxy.Transport != nil {
		t.Errorf("proxy.Transport = %#v, want nil (default transport) for TCP upstream", proxy.Transport)
	}
}

func TestNewReverseProxy_UnixEndToEnd(t *testing.T) {
	var gotAuth, gotHost, gotPath string
	socketPath := newUnixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotHost = r.Host
		gotPath = r.URL.Path
		_, _ = fmt.Fprint(w, "hello from uds")
	}))

	proxy, err := newReverseProxy("unix://"+socketPath, "upstream-token")
	if err != nil {
		t.Fatalf("newReverseProxy() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://proxy.example.com/mcp", nil)
	req.Header.Set("Authorization", "Bearer client-token")
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body=%q)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if body := rec.Body.String(); body != "hello from uds" {
		t.Errorf("body = %q, want %q", body, "hello from uds")
	}
	if want := "Bearer upstream-token"; gotAuth != want {
		t.Errorf("upstream Authorization = %q, want %q", gotAuth, want)
	}
	if want := "proxy.example.com"; gotHost != want {
		t.Errorf("upstream Host = %q, want %q (dummy unix host must not leak)", gotHost, want)
	}
	if want := "/mcp"; gotPath != want {
		t.Errorf("upstream path = %q, want %q", gotPath, want)
	}
}

func TestNewReverseProxy_UnixStreamsIncrementally(t *testing.T) {
	release := make(chan struct{})
	socketPath := newUnixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprint(w, "data: first\n\n")
		flusher.Flush()
		<-release
		_, _ = fmt.Fprint(w, "data: second\n\n")
		flusher.Flush()
	}))

	proxy, err := newReverseProxy("unix://"+socketPath, "")
	if err != nil {
		t.Fatalf("newReverseProxy() error: %v", err)
	}

	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(proxyServer.URL + "/events")
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	reader := bufio.NewReader(resp.Body)
	// 2 チャンク目は release されるまで書かれないため、1 チャンク目が
	// 期限内に届けば flush-through されている。
	if got := readDataLine(t, reader, 2*time.Second); got != "data: first" {
		t.Fatalf("first chunk = %q, want %q", got, "data: first")
	}
	close(release)
	if got := readDataLine(t, reader, 2*time.Second); got != "data: second" {
		t.Errorf("second chunk = %q, want %q", got, "data: second")
	}
}

// readDataLine は次の "data: " 行を timeout 以内に読み取る。
func readDataLine(t *testing.T, r *bufio.Reader, timeout time.Duration) string {
	t.Helper()

	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				ch <- result{err: err}
				return
			}
			if line = strings.TrimRight(line, "\r\n"); strings.HasPrefix(line, "data: ") {
				ch <- result{line: line}
				return
			}
		}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("read error: %v", res.err)
		}
		return res.line
	case <-time.After(timeout):
		t.Fatalf("no data line received within %v", timeout)
		return ""
	}
}

func TestPrintUsage_DocumentsUnixUpstream(t *testing.T) {
	var buf bytes.Buffer
	flag.CommandLine.SetOutput(&buf)
	defer flag.CommandLine.SetOutput(os.Stderr)

	printUsage()

	if got := buf.String(); !strings.Contains(got, "unix:///") {
		t.Errorf("expected unix:/// upstream notation documented in usage output, got:\n%s", got)
	}
}
