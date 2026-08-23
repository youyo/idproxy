package idproxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CIMD（Client ID Metadata Documents）は client_id を https URL とし、
// その URL から取得した metadata document でクライアントを識別する仕組み
// （MCP 2026-07-28 / draft-ietf-oauth-client-id-metadata-document-00）。
// DCR（RFC 7591）とは client_id の形式で一意に区別でき、両者は共存する。
//
// 取得した document は Store には保存せず、プロセス内の TTL キャッシュに閉じる。
// 公開ドキュメントである CIMD は取り直しが可能なため共有ストアである必要がなく、
// DCR の client_id 名前空間と backend 実装を汚さないことを優先している。
const (
	// cimdFetchTimeout は metadata document 取得の全体タイムアウト。
	cimdFetchTimeout = 5 * time.Second
	// cimdMaxBodySize は受理する応答本文の上限（CIMD draft §6.6 の推奨）。
	cimdMaxBodySize = 5 * 1024
	// cimdDefaultTTL は Cache-Control が無い応答に適用するキャッシュ期間。
	cimdDefaultTTL = 15 * time.Minute
	// cimdMinTTL / cimdMaxTTL は Cache-Control: max-age のクランプ境界。
	// 下限は 0 秒連打による fetch 増幅を、上限は失効したクライアントの残留を防ぐ。
	cimdMinTTL = 60 * time.Second
	cimdMaxTTL = 24 * time.Hour
	// cimdMaxCacheEntries はキャッシュのエントリ数上限。
	// client_id は未認証入力なので、無制限に成長させない。
	cimdMaxCacheEntries = 256
)

// cimdBlockedRanges は net.IP の判定メソッドでは表現されない拒否レンジ。
// CGNAT はクラウド環境の内部 API に、IPv6 ULA は内部ネットワークに使われる。
var cimdBlockedRanges = []struct {
	name string
	cidr string
}{
	{"CGNAT", "100.64.0.0/10"},
	{"IPv6 ULA", "fc00::/7"},
}

// cimdBlockedNets は cimdBlockedRanges をパースしたもの。
var cimdBlockedNets = func() []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cimdBlockedRanges))
	for _, r := range cimdBlockedRanges {
		_, n, err := net.ParseCIDR(r.cidr)
		if err != nil {
			panic("idproxy: invalid CIMD blocked range " + r.cidr)
		}
		nets = append(nets, n)
	}
	return nets
}()

// isCIMDClientID は client_id が CIMD の URL 形式かを判定する。
// MCP 2026-07-28 は https スキームと path コンポーネントを要求するため、
// DCR が発行する UUID 形式の client_id とは一意に区別できる。
func isCIMDClientID(clientID string) bool {
	u, err := url.Parse(clientID)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Host != "" && u.Path != "" && u.Path != "/"
}

// denyInternalIP は内部ネットワークへ向く接続先 IP を拒否する（SSRF 対策）。
// 拒否した理由はエラーに含めるが、認可応答には出さない。
func denyInternalIP(ip net.IP) error {
	if ip == nil {
		return errors.New("cimd: nil ip")
	}
	// IPv4-mapped IPv6（::ffff:127.0.0.1 等）を IPv4 として評価する。
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	switch {
	case ip.IsLoopback():
		return fmt.Errorf("cimd: blocked loopback address %s", ip)
	case ip.IsPrivate():
		return fmt.Errorf("cimd: blocked private address %s", ip)
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return fmt.Errorf("cimd: blocked link-local address %s", ip)
	case ip.IsUnspecified():
		return fmt.Errorf("cimd: blocked unspecified address %s", ip)
	case ip.IsMulticast(), ip.IsInterfaceLocalMulticast():
		return fmt.Errorf("cimd: blocked multicast address %s", ip)
	}

	for i, n := range cimdBlockedNets {
		if n.Contains(ip) {
			return fmt.Errorf("cimd: blocked %s address %s", cimdBlockedRanges[i].name, ip)
		}
	}
	return nil
}

// cimdCacheEntry は解決済みクライアントとその失効時刻。
type cimdCacheEntry struct {
	client    *ClientData
	expiresAt time.Time
}

// cimdFetcher は CIMD metadata document の取得・検証・キャッシュを担う。
type cimdFetcher struct {
	httpClient *http.Client
	// allowIP は接続先 IP の許可ポリシー。DialContext から呼ばれる。
	allowIP func(net.IP) error
	// resolver は接続先ホスト名の名前解決に使う。
	resolver *net.Resolver
	// now は現在時刻の取得（テストでキャッシュ期限を進めるために差し替える）。
	now func() time.Time
	// maxEntries はキャッシュのエントリ数上限。
	maxEntries int

	mu    sync.RWMutex
	cache map[string]cimdCacheEntry
}

// newCIMDFetcher は allowIP を接続先 IP ポリシーとする cimdFetcher を構築する。
// 本番の構築経路（NewOAuthServer）は常に denyInternalIP を渡す。
func newCIMDFetcher(allowIP func(net.IP) error) *cimdFetcher {
	f := &cimdFetcher{
		allowIP:    allowIP,
		resolver:   net.DefaultResolver,
		now:        time.Now,
		maxEntries: cimdMaxCacheEntries,
		cache:      make(map[string]cimdCacheEntry),
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = f.dialContext
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}

	f.httpClient = &http.Client{
		Timeout:   cimdFetchTimeout,
		Transport: transport,
		// リダイレクトは追跡先の再検証より禁止するほうが攻撃面が小さい。
		// CIMD の client_id URL は本来リダイレクトを必要としない。
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return fmt.Errorf("cimd: redirect to %s is not allowed", req.URL)
		},
	}

	return f
}

// dialContext はホスト名を自前で解決し、許可ポリシーを通った IP アドレスへ直接 dial する
// （resolve-then-dial-by-IP）。検査した IP と実際に接続する IP を一致させることで、
// 検証時と接続時で解決結果が変わる DNS rebinding / TOCTOU を塞ぐ。
func (f *cimdFetcher) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	addrs, err := f.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("cimd: no address for %s", host)
	}

	// 1 つでも拒否対象があれば接続しない（fail-closed）。
	for _, a := range addrs {
		if err := f.allowIP(a.IP); err != nil {
			return nil, err
		}
	}

	var dialer net.Dialer
	var lastErr error
	for _, a := range addrs {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(a.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// resolve は clientID（CIMD の URL）からクライアント情報を解決する。
// キャッシュが有効ならそれを返し、無効なら metadata document を取得・検証する。
// 取得や検証に失敗した場合は古いキャッシュを返さずエラーにする（fail-closed）。
// 失効した metadata で認可を通すのが最悪の失敗様式であるため。
func (f *cimdFetcher) resolve(ctx context.Context, clientID string) (*ClientData, error) {
	if !isCIMDClientID(clientID) {
		return nil, fmt.Errorf("cimd: %q is not a client id metadata document URL", clientID)
	}

	if client, ok := f.lookupCache(clientID); ok {
		return client, nil
	}

	client, ttl, err := f.fetch(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if ttl > 0 {
		f.storeCache(clientID, client, ttl)
	}
	return client, nil
}

// lookupCache は有効期限内のキャッシュを引く。
func (f *cimdFetcher) lookupCache(clientID string) (*ClientData, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	entry, ok := f.cache[clientID]
	if !ok || !f.now().Before(entry.expiresAt) {
		return nil, false
	}
	return entry.client, true
}

// storeCache はキャッシュへ登録する。上限を超える場合は失効済みエントリを掃除し、
// それでも空かないときは期限が最も近いエントリを捨てる。
func (f *cimdFetcher) storeCache(clientID string, client *ClientData, ttl time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := f.now()
	if _, exists := f.cache[clientID]; !exists && len(f.cache) >= f.maxEntries {
		for k, e := range f.cache {
			if !now.Before(e.expiresAt) {
				delete(f.cache, k)
			}
		}
	}
	for len(f.cache) >= f.maxEntries {
		var oldestKey string
		var oldest time.Time
		for k, e := range f.cache {
			if oldestKey == "" || e.expiresAt.Before(oldest) {
				oldestKey, oldest = k, e.expiresAt
			}
		}
		delete(f.cache, oldestKey)
	}

	f.cache[clientID] = cimdCacheEntry{client: client, expiresAt: now.Add(ttl)}
}

// cimdDocument は metadata document の JSON 表現。
type cimdDocument struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

// fetch は metadata document を取得・検証し、ClientData とキャッシュ期間を返す。
// キャッシュ期間が 0 の場合はキャッシュしない（no-store / no-cache）。
func (f *cimdFetcher) fetch(ctx context.Context, clientID string) (*ClientData, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("cimd: fetch failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("cimd: unexpected status %d", resp.StatusCode)
	}
	if mediaType, _, _ := strings.Cut(resp.Header.Get("Content-Type"), ";"); !strings.EqualFold(strings.TrimSpace(mediaType), "application/json") {
		return nil, 0, fmt.Errorf("cimd: unexpected content type %q", resp.Header.Get("Content-Type"))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxBodySize+1))
	if err != nil {
		return nil, 0, fmt.Errorf("cimd: failed to read body: %w", err)
	}
	if len(body) > cimdMaxBodySize {
		return nil, 0, fmt.Errorf("cimd: metadata document exceeds %d bytes", cimdMaxBodySize)
	}

	var doc cimdDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, 0, fmt.Errorf("cimd: failed to decode metadata document: %w", err)
	}

	client, err := validateCIMDDocument(clientID, &doc)
	if err != nil {
		return nil, 0, err
	}
	return client, cimdCacheTTL(resp.Header), nil
}

// validateCIMDDocument は metadata document を検証し ClientData へ変換する。
// client_id の一致（MUST）と redirect_uris の健全性を確認する。
func validateCIMDDocument(clientID string, doc *cimdDocument) (*ClientData, error) {
	if doc.ClientID != clientID {
		return nil, fmt.Errorf("cimd: client_id mismatch: document has %q", doc.ClientID)
	}
	if len(doc.RedirectURIs) == 0 {
		return nil, errors.New("cimd: redirect_uris is required")
	}
	for _, uri := range doc.RedirectURIs {
		u, err := url.Parse(uri)
		if err != nil {
			return nil, fmt.Errorf("cimd: invalid redirect_uri %q: %w", uri, err)
		}
		if u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("cimd: redirect_uri %q must be absolute", uri)
		}
	}

	return &ClientData{
		ClientID:                doc.ClientID,
		ClientName:              doc.ClientName,
		RedirectURIs:            doc.RedirectURIs,
		GrantTypes:              doc.GrantTypes,
		ResponseTypes:           doc.ResponseTypes,
		TokenEndpointAuthMethod: doc.TokenEndpointAuthMethod,
		Scope:                   doc.Scope,
	}, nil
}

// cimdCacheTTL は Cache-Control からキャッシュ期間を決める。
// max-age を [cimdMinTTL, cimdMaxTTL] にクランプし、指定が無ければ既定値、
// no-store / no-cache なら 0（キャッシュしない）を返す。
func cimdCacheTTL(header http.Header) time.Duration {
	ttl := cimdDefaultTTL

	for _, value := range header.Values("Cache-Control") {
		for _, directive := range strings.Split(value, ",") {
			directive = strings.TrimSpace(directive)
			name, arg, _ := strings.Cut(directive, "=")

			switch strings.ToLower(strings.TrimSpace(name)) {
			case "no-store", "no-cache":
				return 0
			case "max-age":
				seconds, err := strconv.Atoi(strings.TrimSpace(arg))
				if err != nil {
					continue
				}
				ttl = time.Duration(seconds) * time.Second
			}
		}
	}

	return min(max(ttl, cimdMinTTL), cimdMaxTTL)
}
