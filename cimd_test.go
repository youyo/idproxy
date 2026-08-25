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
	"sync"
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
		// userinfo は outbound の Authorization: Basic ヘッダーに化けるため拒否する。
		{"userinfo with password", "https://user:pass@example.com/client.json", false},
		{"userinfo without password", "https://user@example.com/client.json", false},
		{"query", "https://example.com/client.json?a=b", false},
		{"empty query marker", "https://example.com/client.json?", false},
		{"fragment", "https://example.com/client.json#frag", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCIMDClientID(tt.clientID); got != tt.want {
				t.Errorf("isCIMDClientID(%q) = %v, want %v", tt.clientID, got, tt.want)
			}
		})
	}
}

// TestCIMD_CanonicalClientID はキャッシュキーの正規化を検証する。
func TestCIMD_CanonicalClientID(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		want     string
	}{
		{"already canonical", "https://example.com/client.json", "https://example.com/client.json"},
		{"uppercase host", "https://EXAMPLE.com/client.json", "https://example.com/client.json"},
		{"default port dropped", "https://example.com:443/client.json", "https://example.com/client.json"},
		{"uppercase host with default port", "https://ExAmPlE.COM:443/client.json", "https://example.com/client.json"},
		{"non default port kept", "https://example.com:8443/client.json", "https://example.com:8443/client.json"},
		{"ipv6 literal", "https://[2001:db8::1]/client.json", "https://[2001:db8::1]/client.json"},
		{"ipv6 literal with default port", "https://[2001:DB8::1]:443/client.json", "https://[2001:db8::1]/client.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := parseCIMDClientID(tt.clientID)
			if err != nil {
				t.Fatalf("parseCIMDClientID(%q) failed: %v", tt.clientID, err)
			}
			if got := canonicalCIMDClientID(u); got != tt.want {
				t.Errorf("canonicalCIMDClientID(%q) = %q, want %q", tt.clientID, got, tt.want)
			}
		})
	}
}

// TestCIMD_Resolve_ReturnsDefensiveCopy は resolve の戻り値を書き換えても
// キャッシュ(プロセス共有・未認証入力がキー)が汚染されないことを検証する。
func TestCIMD_Resolve_ReturnsDefensiveCopy(t *testing.T) {
	ts := newCIMDDocumentServer(t, validCIMDDocument())
	f := newTestCIMDFetcher(t, ts)
	clientID := ts.clientID("/client.json")

	first, err := f.resolve(context.Background(), clientID)
	if err != nil {
		t.Fatalf("resolve() failed: %v", err)
	}
	first.RedirectURIs[0] = "https://evil.example.com/cb"
	first.ClientName = "Poisoned"

	second, err := f.resolve(context.Background(), clientID)
	if err != nil {
		t.Fatalf("second resolve() failed: %v", err)
	}
	if got := ts.fetches.Load(); got != 1 {
		t.Fatalf("expected the second resolve to hit the cache, got %d fetches", got)
	}
	if second.RedirectURIs[0] != "http://localhost:3000/callback" {
		t.Errorf("cache was poisoned via the returned slice: %v", second.RedirectURIs)
	}
	if second.ClientName != "CIMD Test App" {
		t.Errorf("cache was poisoned via the returned struct: %q", second.ClientName)
	}

	// 2 回目の戻り値を書き換えても 3 回目には影響しない。
	second.RedirectURIs[0] = "https://evil.example.com/cb"
	third, err := f.resolve(context.Background(), clientID)
	if err != nil {
		t.Fatalf("third resolve() failed: %v", err)
	}
	if third.RedirectURIs[0] != "http://localhost:3000/callback" {
		t.Errorf("cache was poisoned via a cached-copy slice: %v", third.RedirectURIs)
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

		// NAT64（DNS64/NAT64 の IPv6-only ネットワークで実際に到達しうる）
		{"NAT64 loopback", "64:ff9b::7f00:1", true},
		{"NAT64 link-local metadata", "64:ff9b::a9fe:a9fe", true},
		{"NAT64 private", "64:ff9b::a00:1", true},
		{"NAT64 Azure WireServer", "64:ff9b::a83f:8110", true},
		{"NAT64 public", "64:ff9b::808:808", false},

		// IPv4-compatible IPv6（廃止済みだが解決結果としては現れうる）
		{"IPv4-compatible loopback", "::7f00:1", true},
		{"IPv4-compatible metadata", "::a9fe:a9fe", true},

		// 6to4
		{"6to4 loopback", "2002:7f00:1::1", true},
		{"6to4 private", "2002:a00:1::1", true},
		{"6to4 metadata", "2002:a9fe:a9fe::1", true},
		{"6to4 public", "2002:808:808::1", false},

		// その他のレンジ
		{"IPv4 broadcast", "255.255.255.255", true},
		{"IPv4 this-network non-zero", "0.1.2.3", true},
		{"IPv6 site-local deprecated", "fec0::1", true},
		{"IPv6 documentation", "2001:db8::1", true},
		{"IETF protocol assignments", "192.0.0.1", true},
		{"benchmarking", "198.18.0.1", true},
		{"Azure WireServer", "168.63.129.16", true},

		{"public IPv4", "8.8.8.8", false},
		{"public IPv4 below CGNAT", "100.63.255.255", false},
		{"public IPv4 above CGNAT", "100.128.0.0", false},
		{"public IPv4 next to Azure WireServer", "168.63.129.17", false},
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
			// 拒否理由（対象 IP を含む）はエラーに残す。ログ専用で、認可応答には出さない。
			if tt.blocked && err != nil && !strings.Contains(err.Error(), ip.String()) {
				t.Errorf("denyInternalIP(%s) error %q should name the blocked address", tt.ip, err)
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
	// カスタムスキーム（myapp://cb）は validateCIMDDocument が拒否するようになったため、
	// 2 件目は https を使う。
	doc["redirect_uris"] = []string{"http://localhost:3000/callback", "https://app.example.com/cb"}
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
		{
			// http の外部ホストは攻撃者が用意した平文の受け口になりうるため拒否する。
			name: "redirect_uri http on remote host",
			doc: map[string]any{
				"client_name":   "Plain HTTP App",
				"redirect_uris": []string{"http://evil.example.com/cb"},
			},
		},
		{
			// カスタムスキームは端末上の任意アプリに横取りされうるため拒否する。
			name: "redirect_uri custom scheme",
			doc: map[string]any{
				"client_name":   "Custom Scheme App",
				"redirect_uris": []string{"myapp://cb"},
			},
		},
		{
			name: "redirect_uri mixes https and custom scheme",
			doc: map[string]any{
				"client_name":   "Mixed App",
				"redirect_uris": []string{"https://app.example.com/cb", "myapp://cb"},
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
	if got := cap(f.sem); got != cimdMaxConcurrentFetches {
		t.Errorf("expected fetch concurrency limit %d, got %d", cimdMaxConcurrentFetches, got)
	}
}

// TestCIMD_Fetcher_NoProxy は Transport がプロキシを一切使わないことを検証する。
// プロキシ経由になると dialContext の IP ポリシー（resolve-then-dial-by-IP）が
// プロキシの IP にしか効かず、実際の接続先への SSRF 防御が無効化される。
func TestCIMD_Fetcher_NoProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.example.com:3128")
	t.Setenv("HTTP_PROXY", "http://proxy.example.com:3128")

	f := newCIMDFetcher(denyInternalIP)

	tr, ok := f.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", f.httpClient.Transport)
	}
	if tr.Proxy != nil {
		req := httptest.NewRequest(http.MethodGet, "https://example.com/client.json", nil)
		proxyURL, err := tr.Proxy(req)
		t.Fatalf("expected Transport.Proxy to be nil, got a proxy func returning (%v, %v)", proxyURL, err)
	}
}

// TestCIMD_Resolve_NegativeCache は失敗した client_id が短期間キャッシュされ、
// その間は再 fetch されないこと、かつ常にエラーを返す(成功に化けない)ことを検証する。
func TestCIMD_Resolve_NegativeCache(t *testing.T) {
	ts := newCIMDTestServer(t, func(w http.ResponseWriter, r *http.Request, count int64) {
		if count == 1 {
			// 攻撃者のサーバーは no-store を返してキャッシュを無効化しようとする。
			w.Header().Set("Cache-Control", "no-store")
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

	for i := 0; i < 3; i++ {
		if _, err := f.resolve(context.Background(), clientID); err == nil {
			t.Fatalf("resolve() #%d = nil error, want error", i+1)
		}
	}
	if got := ts.fetches.Load(); got != 1 {
		t.Errorf("expected 1 fetch while the failure is negatively cached, got %d", got)
	}

	// ネガティブキャッシュの期限が切れたら再試行する。
	f.now = func() time.Time { return base.Add(cimdNegativeTTL + time.Second) }
	if _, err := f.resolve(context.Background(), clientID); err != nil {
		t.Fatalf("resolve() after negative TTL failed: %v", err)
	}
	if got := ts.fetches.Load(); got != 2 {
		t.Errorf("expected re-fetch after negative TTL, got %d fetches", got)
	}
}

// TestCIMD_Resolve_SingleFlight は同一 client_id への並行 resolve が
// 1 回の fetch にまとまることを検証する。
// キャッシュによる抑止と区別するため、応答は no-store(＝キャッシュしない)にしている。
func TestCIMD_Resolve_SingleFlight(t *testing.T) {
	release := make(chan struct{})
	ts := newCIMDTestServer(t, func(w http.ResponseWriter, r *http.Request, _ int64) {
		<-release
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		writeCIMDDocument(w, r, validCIMDDocument())
	})
	f := newTestCIMDFetcher(t, ts)
	clientID := ts.clientID("/client.json")

	const callers = 8
	errs := make(chan error, callers)
	resolve := func() {
		_, err := f.resolve(context.Background(), clientID)
		errs <- err
	}

	// 先着の 1 本がハンドラへ到達し、inflight に登録されるまで待つ。
	go resolve()
	waitForCondition(t, "leader fetch to start", func() bool {
		f.mu.RLock()
		defer f.mu.RUnlock()
		return len(f.inflight) == 1
	})

	var ready sync.WaitGroup
	ready.Add(callers - 1)
	for i := 1; i < callers; i++ {
		go func() {
			ready.Done()
			resolve()
		}()
	}
	ready.Wait()
	// 後続が resolve に入り、待ち合わせに乗るまでの猶予。
	time.Sleep(50 * time.Millisecond)
	close(release)

	for i := 0; i < callers; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("resolve() #%d failed: %v", i+1, err)
		}
	}
	if got := ts.fetches.Load(); got != 1 {
		t.Errorf("expected concurrent resolves to collapse into 1 fetch, got %d", got)
	}
}

// waitForCondition は cond が true になるまで短くポーリングする。
func waitForCondition(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
