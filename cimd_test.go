package idproxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- CIMD（Client ID Metadata Documents）テスト ---

// cimdTestServer は CIMD metadata document を返す TLS テストサーバーと
// fetch 回数カウンタをまとめたもの。
type cimdTestServer struct {
	*httptest.Server
	// fetches は metadata document への HTTP リクエスト回数。
	fetches atomic.Int64
}

// clientID は metadata document を配布する URL（＝ CIMD の client_id）。
// path は "/client.json" のように先頭スラッシュ付きで渡す。
func (s *cimdTestServer) clientID(path string) string {
	return s.URL + path
}

// newCIMDTestServer は handler をラップした TLS テストサーバーを立てる。
// handler には fetch のたびに現在の回数（1 起算）が渡される。
func newCIMDTestServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, count int64)) *cimdTestServer {
	t.Helper()

	ts := &cimdTestServer{}
	ts.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(w, r, ts.fetches.Add(1))
	}))
	t.Cleanup(ts.Close)
	return ts
}

// newCIMDDocumentServer は doc を application/json で返すテストサーバーを立てる。
// doc に client_id が無い場合はリクエスト URL（＝正しい client_id）を補って返す。
func newCIMDDocumentServer(t *testing.T, doc map[string]any) *cimdTestServer {
	t.Helper()

	return newCIMDTestServer(t, func(w http.ResponseWriter, r *http.Request, _ int64) {
		w.Header().Set("Content-Type", "application/json")
		writeCIMDDocument(w, r, doc)
	})
}

// writeCIMDDocument は doc の client_id をリクエスト URL で補完して JSON 出力する。
func writeCIMDDocument(w http.ResponseWriter, r *http.Request, doc map[string]any) {
	body := make(map[string]any, len(doc)+1)
	for k, v := range doc {
		body[k] = v
	}
	if body["client_id"] == nil {
		body["client_id"] = "https://" + r.Host + r.URL.RequestURI()
	}
	_ = json.NewEncoder(w).Encode(body)
}

// newTestCIMDFetcher は接続先 IP 検査を無効化した cimdFetcher を組み立てる。
// httptest サーバーは loopback で待ち受けるため、本番ポリシー（denyInternalIP）では
// 到達できない。本番構築経路（NewOAuthServer）は常に denyInternalIP を使う。
func newTestCIMDFetcher(t *testing.T, ts *cimdTestServer) *cimdFetcher {
	t.Helper()

	f := newCIMDFetcher(func(net.IP) error { return nil })
	trustCIMDTestServer(t, f, ts)
	return f
}

// trustCIMDTestServer は fetcher の Transport にテストサーバーの CA を信頼させる。
func trustCIMDTestServer(t *testing.T, f *cimdFetcher, ts *cimdTestServer) {
	t.Helper()

	tr, ok := f.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", f.httpClient.Transport)
	}
	src, ok := ts.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected test server *http.Transport, got %T", ts.Client().Transport)
	}
	tr.TLSClientConfig = src.TLSClientConfig.Clone()
}

// validCIMDDocument は必須フィールドを備えた metadata document を返す。
func validCIMDDocument() map[string]any {
	return map[string]any{
		"client_name":   "CIMD Test App",
		"redirect_uris": []string{"http://localhost:3000/callback"},
	}
}

// --- isCIMDClientID ---

func TestCIMD_IsCIMDClientID(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		want     bool
	}{
		{"https with path", "https://example.com/client.json", true},
		{"https with nested path", "https://example.com/a/b/client.json", true},
		{"https with port and path", "https://example.com:8443/client.json", true},
		{"http scheme", "http://example.com/client.json", false},
		{"https without path", "https://example.com", false},
		{"https with root path only", "https://example.com/", false},
		{"https without host", "https:///client.json", false},
		{"dcr uuid", "6ba7b810-9dad-11d1-80b4-00c04fd430c8", false},
		{"empty", "", false},
		{"custom scheme", "ftp://example.com/client.json", false},
		{"not a url", "://", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCIMDClientID(tt.clientID); got != tt.want {
				t.Errorf("isCIMDClientID(%q) = %v, want %v", tt.clientID, got, tt.want)
			}
		})
	}
}

// --- 接続先 IP ポリシー ---

func TestCIMD_DenyInternalIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		{"IPv4 loopback", "127.0.0.1", true},
		{"IPv6 loopback", "::1", true},
		{"RFC1918 10/8", "10.0.0.1", true},
		{"RFC1918 172.16/12", "172.16.0.1", true},
		{"RFC1918 192.168/16", "192.168.1.1", true},
		{"link-local unicast", "169.254.169.254", true},
		{"IPv6 link-local unicast", "fe80::1", true},
		{"link-local multicast", "224.0.0.1", true},
		{"unspecified IPv4", "0.0.0.0", true},
		{"unspecified IPv6", "::", true},
		{"CGNAT lower bound", "100.64.0.0", true},
		{"CGNAT upper bound", "100.127.255.255", true},
		{"IPv6 ULA", "fd00::1", true},
		{"IPv4-mapped loopback", "::ffff:127.0.0.1", true},
		{"IPv4-mapped private", "::ffff:10.0.0.1", true},
		{"public IPv4", "8.8.8.8", false},
		{"public IPv4 below CGNAT", "100.63.255.255", false},
		{"public IPv4 above CGNAT", "100.128.0.0", false},
		{"public IPv6", "2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse test IP %q", tt.ip)
			}
			err := denyInternalIP(ip)
			if tt.blocked && err == nil {
				t.Errorf("denyInternalIP(%s) = nil, want error", tt.ip)
			}
			if !tt.blocked && err != nil {
				t.Errorf("denyInternalIP(%s) = %v, want nil", tt.ip, err)
			}
		})
	}
}

func TestCIMD_DenyInternalIP_Nil(t *testing.T) {
	if err := denyInternalIP(nil); err == nil {
		t.Error("denyInternalIP(nil) = nil, want error")
	}
}

// TestCIMD_Resolve_RejectsLoopbackTarget は本番ポリシーの fetcher が
// loopback へ解決される URL への接続を DialContext 段で拒否することを検証する。
// IP リテラルとホスト名の双方を通すことで、実際に接続する IP に基づく検査
// （resolve-then-dial-by-IP）が効いていることを固定する。
func TestCIMD_Resolve_RejectsLoopbackTarget(t *testing.T) {
	ts := newCIMDDocumentServer(t, validCIMDDocument())

	_, port, err := net.SplitHostPort(strings.TrimPrefix(ts.URL, "https://"))
	if err != nil {
		t.Fatalf("failed to split test server address: %v", err)
	}

	tests := []struct {
		name     string
		clientID string
	}{
		{"IP literal host", ts.clientID("/client.json")},
		{"hostname resolving to loopback", "https://localhost:" + port + "/client.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newCIMDFetcher(denyInternalIP)
			trustCIMDTestServer(t, f, ts)

			if _, err := f.resolve(context.Background(), tt.clientID); err == nil {
				t.Fatal("expected error for loopback target, got nil")
			}
		})
	}
}

// --- fetch / 検証 ---

func TestCIMD_Resolve_Success(t *testing.T) {
	doc := validCIMDDocument()
	doc["redirect_uris"] = []string{"http://localhost:3000/callback", "myapp://cb"}
	doc["scope"] = "openid email"
	ts := newCIMDDocumentServer(t, doc)
	f := newTestCIMDFetcher(t, ts)

	clientID := ts.clientID("/client.json")
	client, err := f.resolve(context.Background(), clientID)
	if err != nil {
		t.Fatalf("resolve() failed: %v", err)
	}

	if client.ClientID != clientID {
		t.Errorf("expected client_id %q, got %q", clientID, client.ClientID)
	}
	if client.ClientName != "CIMD Test App" {
		t.Errorf("expected client_name %q, got %q", "CIMD Test App", client.ClientName)
	}
	if len(client.RedirectURIs) != 2 || client.RedirectURIs[0] != "http://localhost:3000/callback" {
		t.Errorf("unexpected redirect_uris: %v", client.RedirectURIs)
	}
	if client.Scope != "openid email" {
		t.Errorf("expected scope %q, got %q", "openid email", client.Scope)
	}
}

func TestCIMD_Resolve_RejectsInvalidDocument(t *testing.T) {
	tests := []struct {
		name string
		doc  map[string]any
	}{
		{
			name: "client_id mismatch",
			doc: map[string]any{
				"client_id":     "https://attacker.example.com/client.json",
				"client_name":   "Evil App",
				"redirect_uris": []string{"http://localhost:3000/callback"},
			},
		},
		{
			name: "redirect_uris missing",
			doc:  map[string]any{"client_name": "No Redirect App"},
		},
		{
			name: "redirect_uris empty",
			doc: map[string]any{
				"client_name":   "Empty Redirect App",
				"redirect_uris": []string{},
			},
		},
		{
			name: "redirect_uri without scheme",
			doc: map[string]any{
				"client_name":   "Relative Redirect App",
				"redirect_uris": []string{"/callback"},
			},
		},
		{
			name: "redirect_uri without host",
			doc: map[string]any{
				"client_name":   "Hostless Redirect App",
				"redirect_uris": []string{"https:///callback"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newCIMDDocumentServer(t, tt.doc)
			f := newTestCIMDFetcher(t, ts)

			if _, err := f.resolve(context.Background(), ts.clientID("/client.json")); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// TestCIMD_Resolve_RejectsMalformedJSON は JSON として不正な応答を拒否することを検証する。
func TestCIMD_Resolve_RejectsMalformedJSON(t *testing.T) {
	ts := newCIMDTestServer(t, func(w http.ResponseWriter, _ *http.Request, _ int64) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not json"))
	})
	f := newTestCIMDFetcher(t, ts)

	if _, err := f.resolve(context.Background(), ts.clientID("/client.json")); err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

// TestCIMD_Resolve_RejectsRedirect はリダイレクト応答を追跡せず拒否することを検証する。
func TestCIMD_Resolve_RejectsRedirect(t *testing.T) {
	ts := newCIMDTestServer(t, func(w http.ResponseWriter, r *http.Request, _ int64) {
		http.Redirect(w, r, "https://elsewhere.example.com/client.json", http.StatusFound)
	})
	f := newTestCIMDFetcher(t, ts)

	if _, err := f.resolve(context.Background(), ts.clientID("/client.json")); err == nil {
		t.Fatal("expected error for redirect response, got nil")
	}
}

// TestCIMD_Resolve_RejectsOversizedBody は 5KB を超える応答本文を拒否することを検証する。
func TestCIMD_Resolve_RejectsOversizedBody(t *testing.T) {
	ts := newCIMDTestServer(t, func(w http.ResponseWriter, r *http.Request, _ int64) {
		w.Header().Set("Content-Type", "application/json")
		doc := validCIMDDocument()
		doc["client_name"] = strings.Repeat("A", cimdMaxBodySize)
		writeCIMDDocument(w, r, doc)
	})
	f := newTestCIMDFetcher(t, ts)

	if _, err := f.resolve(context.Background(), ts.clientID("/client.json")); err == nil {
		t.Fatal("expected error for oversized body, got nil")
	}
}

func TestCIMD_Resolve_RejectsBadResponse(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
	}{
		{"not found", http.StatusNotFound, "application/json"},
		{"server error", http.StatusInternalServerError, "application/json"},
		{"no content type", http.StatusOK, ""},
		{"text/html", http.StatusOK, "text/html; charset=utf-8"},
		{"application/xml", http.StatusOK, "application/xml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newCIMDTestServer(t, func(w http.ResponseWriter, r *http.Request, _ int64) {
				if tt.contentType != "" {
					w.Header().Set("Content-Type", tt.contentType)
				}
				w.WriteHeader(tt.status)
				writeCIMDDocument(w, r, validCIMDDocument())
			})
			f := newTestCIMDFetcher(t, ts)

			if _, err := f.resolve(context.Background(), ts.clientID("/client.json")); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// TestCIMD_Resolve_AcceptsContentTypeWithParameters は
// application/json; charset=utf-8 のようなパラメータ付きを受理することを検証する。
func TestCIMD_Resolve_AcceptsContentTypeWithParameters(t *testing.T) {
	ts := newCIMDTestServer(t, func(w http.ResponseWriter, r *http.Request, _ int64) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		writeCIMDDocument(w, r, validCIMDDocument())
	})
	f := newTestCIMDFetcher(t, ts)

	if _, err := f.resolve(context.Background(), ts.clientID("/client.json")); err != nil {
		t.Fatalf("resolve() failed: %v", err)
	}
}

// TestCIMD_Resolve_RejectsNonCIMDClientID は CIMD 形式でない client_id では
// HTTP fetch を発行せずエラーにすることを検証する。
func TestCIMD_Resolve_RejectsNonCIMDClientID(t *testing.T) {
	ts := newCIMDDocumentServer(t, validCIMDDocument())
	f := newTestCIMDFetcher(t, ts)

	if _, err := f.resolve(context.Background(), "6ba7b810-9dad-11d1-80b4-00c04fd430c8"); err == nil {
		t.Fatal("expected error for non-CIMD client_id, got nil")
	}
	if got := ts.fetches.Load(); got != 0 {
		t.Errorf("expected no fetch for non-CIMD client_id, got %d", got)
	}
}

// --- キャッシュ ---

// TestCIMD_Resolve_CachesUntilTTL は TTL 内は再 fetch されず、
// TTL 経過後は再 fetch されることを検証する。
func TestCIMD_Resolve_CachesUntilTTL(t *testing.T) {
	ts := newCIMDDocumentServer(t, validCIMDDocument())
	f := newTestCIMDFetcher(t, ts)

	base := time.Now()
	f.now = func() time.Time { return base }

	clientID := ts.clientID("/client.json")
	for i := 0; i < 3; i++ {
		if _, err := f.resolve(context.Background(), clientID); err != nil {
			t.Fatalf("resolve() #%d failed: %v", i+1, err)
		}
	}
	if got := ts.fetches.Load(); got != 1 {
		t.Fatalf("expected 1 fetch within TTL, got %d", got)
	}

	f.now = func() time.Time { return base.Add(cimdDefaultTTL + time.Second) }
	if _, err := f.resolve(context.Background(), clientID); err != nil {
		t.Fatalf("resolve() after TTL failed: %v", err)
	}
	if got := ts.fetches.Load(); got != 2 {
		t.Errorf("expected re-fetch after TTL, got %d fetches", got)
	}
}

// TestCIMD_Resolve_CacheControl は Cache-Control の max-age が TTL に反映され、
// [cimdMinTTL, cimdMaxTTL] にクランプされること、no-store / no-cache では
// キャッシュされないことを検証する。
func TestCIMD_Resolve_CacheControl(t *testing.T) {
	tests := []struct {
		name         string
		cacheControl string
		wantTTL      time.Duration
		wantCached   bool
	}{
		{"max-age honored", "max-age=3600", time.Hour, true},
		{"max-age clamped to min", "max-age=1", cimdMinTTL, true},
		{"max-age clamped to max", "max-age=604800", cimdMaxTTL, true},
		{"max-age zero clamped to min", "max-age=0", cimdMinTTL, true},
		{"no header falls back to default", "", cimdDefaultTTL, true},
		{"public with max-age", "public, max-age=120", 120 * time.Second, true},
		{"no-store", "no-store", 0, false},
		{"no-cache", "no-cache", 0, false},
		{"no-store wins over max-age", "max-age=3600, no-store", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newCIMDTestServer(t, func(w http.ResponseWriter, r *http.Request, _ int64) {
				if tt.cacheControl != "" {
					w.Header().Set("Cache-Control", tt.cacheControl)
				}
				w.Header().Set("Content-Type", "application/json")
				writeCIMDDocument(w, r, validCIMDDocument())
			})
			f := newTestCIMDFetcher(t, ts)

			base := time.Now()
			f.now = func() time.Time { return base }

			clientID := ts.clientID("/client.json")
			if _, err := f.resolve(context.Background(), clientID); err != nil {
				t.Fatalf("resolve() failed: %v", err)
			}

			if !tt.wantCached {
				if _, err := f.resolve(context.Background(), clientID); err != nil {
					t.Fatalf("second resolve() failed: %v", err)
				}
				if got := ts.fetches.Load(); got != 2 {
					t.Errorf("expected no caching for %q, got %d fetches", tt.cacheControl, got)
				}
				return
			}

			// TTL 直前はキャッシュヒット、TTL 経過後は再 fetch。
			f.now = func() time.Time { return base.Add(tt.wantTTL - time.Second) }
			if _, err := f.resolve(context.Background(), clientID); err != nil {
				t.Fatalf("resolve() before TTL failed: %v", err)
			}
			if got := ts.fetches.Load(); got != 1 {
				t.Fatalf("expected cache hit before TTL %v, got %d fetches", tt.wantTTL, got)
			}

			f.now = func() time.Time { return base.Add(tt.wantTTL + time.Second) }
			if _, err := f.resolve(context.Background(), clientID); err != nil {
				t.Fatalf("resolve() after TTL failed: %v", err)
			}
			if got := ts.fetches.Load(); got != 2 {
				t.Errorf("expected re-fetch after TTL %v, got %d fetches", tt.wantTTL, got)
			}
		})
	}
}

// TestCIMD_Resolve_FailClosedOnFetchFailure は TTL 経過後の fetch が失敗したとき
// 古いキャッシュを返さずエラーにする（fail-closed）ことを検証する。
func TestCIMD_Resolve_FailClosedOnFetchFailure(t *testing.T) {
	ts := newCIMDTestServer(t, func(w http.ResponseWriter, r *http.Request, count int64) {
		if count > 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		writeCIMDDocument(w, r, validCIMDDocument())
	})
	f := newTestCIMDFetcher(t, ts)

	base := time.Now()
	f.now = func() time.Time { return base }
	clientID := ts.clientID("/client.json")
	if _, err := f.resolve(context.Background(), clientID); err != nil {
		t.Fatalf("resolve() failed: %v", err)
	}

	f.now = func() time.Time { return base.Add(cimdDefaultTTL + time.Second) }
	if _, err := f.resolve(context.Background(), clientID); err == nil {
		t.Fatal("expected error after cache expiry with failing upstream, got nil (stale cache served)")
	}
}

// TestCIMD_Resolve_EvictsWhenCacheIsFull はエントリ数が上限を超えたとき
// 期限が最も近いエントリから捨てられることを検証する。
func TestCIMD_Resolve_EvictsWhenCacheIsFull(t *testing.T) {
	ts := newCIMDDocumentServer(t, validCIMDDocument())
	f := newTestCIMDFetcher(t, ts)
	f.maxEntries = 2

	base := time.Now()
	clientIDs := make([]string, 3)
	for i := range clientIDs {
		// 登録時刻をずらして期限の近さに差をつける。
		offset := time.Duration(i) * time.Minute
		f.now = func() time.Time { return base.Add(offset) }
		clientIDs[i] = ts.clientID(fmt.Sprintf("/client-%d.json", i))
		if _, err := f.resolve(context.Background(), clientIDs[i]); err != nil {
			t.Fatalf("resolve() #%d failed: %v", i+1, err)
		}
	}

	f.mu.RLock()
	size := len(f.cache)
	_, oldestKept := f.cache[clientIDs[0]]
	_, newestKept := f.cache[clientIDs[2]]
	f.mu.RUnlock()

	if size > f.maxEntries {
		t.Errorf("expected cache size <= %d, got %d", f.maxEntries, size)
	}
	if oldestKept {
		t.Error("expected the entry expiring soonest to be evicted")
	}
	if !newestKept {
		t.Error("expected the most recently fetched entry to be retained")
	}
}

// TestCIMD_Fetcher_ProductionDefaults は本番構築経路の HTTP クライアント設定を検証する。
func TestCIMD_Fetcher_ProductionDefaults(t *testing.T) {
	f := newCIMDFetcher(denyInternalIP)

	tr, ok := f.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", f.httpClient.Transport)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Error("expected TLS MinVersion >= TLS 1.2")
	}
	if f.httpClient.Timeout != cimdFetchTimeout {
		t.Errorf("expected timeout %v, got %v", cimdFetchTimeout, f.httpClient.Timeout)
	}
	if f.maxEntries != cimdMaxCacheEntries {
		t.Errorf("expected maxEntries %d, got %d", cimdMaxCacheEntries, f.maxEntries)
	}
}
