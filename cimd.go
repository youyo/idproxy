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
	"slices"
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
	// cimdMaxConcurrentFetches は同時に実行する metadata document 取得の上限。
	// /authorize の client_id は未認証入力であり、CIMD の解決はセッション確認より前に走るため、
	// 匿名リクエストがそのまま外向き HTTPS GET になる。上限が無いと
	// 攻撃者が選んだホスト・ポートへの大量接続(egress 濫用・ポートスキャン)と
	// goroutine 枯渇の踏み台になるため、小さめの値で頭打ちにする。
	cimdMaxConcurrentFetches = 8
	// cimdNegativeTTL は取得・検証に失敗した client_id を記憶しておく期間。
	// 失敗を短時間キャッシュすることで同じ client_id の連打を 1 回の fetch に抑える。
	// 記憶するのは「失敗した」という事実だけで、認可は必ず失敗させる(fail-closed)。
	cimdNegativeTTL = 30 * time.Second
)

// cimdBlockedRanges は接続を拒否するアドレスレンジの明示的なテーブル。
// net.IP の判定メソッド任せにすると IPv6 側の抜けに気付けないため、
// IPv4 / IPv6 の双方を CIDR で列挙して一箇所で管理する。
var cimdBlockedRanges = []struct {
	name string
	cidr string
}{
	// --- IPv4 ---
	{"IPv4 this-network", "0.0.0.0/8"},
	{"IPv4 loopback", "127.0.0.0/8"},
	{"RFC1918 10/8", "10.0.0.0/8"},
	{"RFC1918 172.16/12", "172.16.0.0/12"},
	{"RFC1918 192.168/16", "192.168.0.0/16"},
	{"CGNAT", "100.64.0.0/10"},
	{"IPv4 link-local", "169.254.0.0/16"},
	// IETF protocol assignments。198.51.100.0/24 等の文書用より広く内部利用されうる。
	{"IETF protocol assignments", "192.0.0.0/24"},
	{"benchmarking", "198.18.0.0/15"},
	// Azure の WireServer。パブリックアドレス空間だが全 Azure VM から到達できる。
	{"Azure WireServer", "168.63.129.16/32"},
	{"IPv4 multicast", "224.0.0.0/4"},
	{"IPv4 broadcast", "255.255.255.255/32"},

	// --- IPv6 ---
	{"IPv6 unspecified", "::/128"},
	{"IPv6 loopback", "::1/128"},
	{"IPv6 ULA", "fc00::/7"},
	{"IPv6 link-local", "fe80::/10"},
	// 廃止済みだが実装によっては今も内部ネットワークに使われている。
	{"IPv6 site-local (deprecated)", "fec0::/10"},
	{"IPv6 multicast", "ff00::/8"},
	{"IPv6 documentation", "2001:db8::/32"},
}

// cimdBlockedNets は cimdBlockedRanges をパースしたもの。
var cimdBlockedNets = parseCIMDCIDRs(func() []string {
	cidrs := make([]string, len(cimdBlockedRanges))
	for i, r := range cimdBlockedRanges {
		cidrs[i] = r.cidr
	}
	return cidrs
}())

// cimdEmbeddedIPv4Prefixes は IPv4 アドレスを内包する IPv6 プレフィックス。
// offset は IPv6 の 16 バイト表現のうち IPv4 が始まるバイト位置。
//
// 【重要・セキュリティ】net.IP.To4 は 4 バイト表現と ::ffff:a.b.c.d しか IPv4 に
// 変換しないため、これらのプレフィックスは IPv4 のポリシーをすり抜ける。
// 例えば DNS64/NAT64 のネットワーク（AWS/GCP の IPv6-only クラスタ等）では
// 64:ff9b::7f00:1 が 127.0.0.1 に、64:ff9b::a9fe:a9fe が 169.254.169.254 に届く。
var cimdEmbeddedIPv4Prefixes = []struct {
	name   string
	cidr   string
	offset int
}{
	{"IPv4-compatible IPv6", "::/96", 12},
	{"NAT64 well-known prefix", "64:ff9b::/96", 12},
	{"6to4", "2002::/16", 2},
}

// cimdEmbeddedIPv4Nets は cimdEmbeddedIPv4Prefixes をパースしたもの。
var cimdEmbeddedIPv4Nets = parseCIMDCIDRs(func() []string {
	cidrs := make([]string, len(cimdEmbeddedIPv4Prefixes))
	for i, p := range cimdEmbeddedIPv4Prefixes {
		cidrs[i] = p.cidr
	}
	return cidrs
}())

// parseCIMDCIDRs は CIDR 文字列を *net.IPNet へ変換する。
// テーブルは定数なので、不正な値はプロセス起動時に panic させる。
func parseCIMDCIDRs(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("idproxy: invalid CIMD blocked range " + cidr)
		}
		nets = append(nets, n)
	}
	return nets
}

// isCIMDClientID は client_id が CIMD の URL 形式かを判定する。
// MCP 2026-07-28 は https スキームと path コンポーネントを要求するため、
// DCR が発行する UUID 形式の client_id とは一意に区別できる。
func isCIMDClientID(clientID string) bool {
	_, err := parseCIMDClientID(clientID)
	return err == nil
}

// parseCIMDClientID は client_id を CIMD の URL として検証する。
// https スキーム・ホスト・path に加え、以下を拒否する。
//
//   - userinfo(https://user:pass@host/path)
//     【重要・セキュリティ】http.Client は req.URL.User から Authorization: Basic
//     ヘッダーを組み立てるため、未認証入力である client_id が
//     外向きリクエストへ任意の資格情報を載せる手段になってしまう。
//   - query / fragment
//     同一 document を指す表記ゆれを増やすだけで CIMD の client_id には不要。
func parseCIMDClientID(clientID string) (*url.URL, error) {
	u, err := url.Parse(clientID)
	if err != nil {
		return nil, fmt.Errorf("cimd: %q is not a valid URL: %w", clientID, err)
	}
	if u.Scheme != "https" || u.Host == "" || u.Path == "" || u.Path == "/" {
		return nil, fmt.Errorf("cimd: %q is not a client id metadata document URL", clientID)
	}
	if u.User != nil {
		return nil, fmt.Errorf("cimd: client_id must not contain userinfo")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("cimd: client_id must not contain a query or fragment")
	}
	return u, nil
}

// canonicalCIMDClientID はキャッシュキー用の正規形を返す。
// ホスト名を小文字化し、既定ポート :443 を落とすことで、
// https://H/p と https://h:443/p を 1 エントリにまとめる。
func canonicalCIMDClientID(u *url.URL) string {
	canonical := *u
	host := strings.ToLower(u.Hostname())
	if port := u.Port(); port != "" && port != "443" {
		canonical.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		// IPv6 リテラルは角括弧を復元する。
		canonical.Host = "[" + host + "]"
	} else {
		canonical.Host = host
	}
	return canonical.String()
}

// cloneClientData は ClientData の防御的コピーを返す。
// キャッシュは未認証入力(client_id)をキーとするプロセス共有の構造なので、
// 共有ポインタを呼び出し側へ渡さない。呼び出し側が書き換えると
// 以降の全リクエストのクライアント定義を汚染できてしまうため。
func cloneClientData(c *ClientData) *ClientData {
	if c == nil {
		return nil
	}
	clone := *c
	clone.RedirectURIs = slices.Clone(c.RedirectURIs)
	clone.GrantTypes = slices.Clone(c.GrantTypes)
	clone.ResponseTypes = slices.Clone(c.ResponseTypes)
	return &clone
}

// denyInternalIP は内部ネットワークへ向く接続先 IP を拒否する（SSRF 対策）。
// 拒否した理由はエラーに含めるが、認可応答には出さない（ログにのみ残る）。
//
// 判定は 2 段構えで行う。
//  1. アドレスそのもの（IPv4 は 4 バイト表現、IPv6 は 16 バイト表現）を拒否テーブルに掛ける
//  2. IPv6 が IPv4 を内包するプレフィックス（NAT64 / 6to4 / IPv4-compatible）なら、
//     埋め込まれた IPv4 を取り出して同じポリシーを再適用する
//
// どちらか一方でも拒否に当たれば接続しない（fail-closed）。
func denyInternalIP(ip net.IP) error {
	if ip == nil {
		return errors.New("cimd: nil ip")
	}

	// IPv4-mapped IPv6（::ffff:127.0.0.1 等）を IPv4 として評価する。
	if v4 := ip.To4(); v4 != nil {
		return denyIPByPolicy(v4)
	}

	ip16 := ip.To16()
	if ip16 == nil {
		return fmt.Errorf("cimd: blocked malformed address %s", ip)
	}
	if err := denyIPByPolicy(ip16); err != nil {
		return err
	}

	for i, n := range cimdEmbeddedIPv4Nets {
		if !n.Contains(ip16) {
			continue
		}
		p := cimdEmbeddedIPv4Prefixes[i]
		embedded := net.IP(ip16[p.offset : p.offset+net.IPv4len]).To4()
		if embedded == nil {
			continue
		}
		if err := denyIPByPolicy(embedded); err != nil {
			return fmt.Errorf("%w (embedded in %s address %s)", err, p.name, ip16)
		}
	}
	return nil
}

// denyIPByPolicy は 1 つのアドレス表現に拒否ポリシーを適用する。
// 明示的な CIDR 拒否テーブルに加え、global unicast であることを積極的な前提条件として要求する
// （これだけでブロードキャスト・unspecified・loopback・multicast・link-local が落ちる）。
func denyIPByPolicy(ip net.IP) error {
	for i, n := range cimdBlockedNets {
		if n.Contains(ip) {
			return fmt.Errorf("cimd: blocked %s address %s", cimdBlockedRanges[i].name, ip)
		}
	}
	if !ip.IsGlobalUnicast() {
		return fmt.Errorf("cimd: blocked non-global-unicast address %s", ip)
	}
	return nil
}

// cimdCacheEntry は解決結果とその失効時刻。
// err が非 nil のエントリはネガティブキャッシュ(失敗の記憶)で、client は nil になる。
type cimdCacheEntry struct {
	client    *ClientData
	err       error
	expiresAt time.Time
}

// cimdFetchCall は同一 client_id への並行 resolve を 1 回の fetch にまとめる待ち合わせ。
// 先着した呼び出しだけが fetch を実行し、後続は done を待って同じ結果を共有する。
type cimdFetchCall struct {
	done   chan struct{}
	client *ClientData
	err    error
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
	// sem は同時 fetch 数を制限するセマフォ。容量が同時実行の上限になる。
	sem chan struct{}

	mu    sync.RWMutex
	cache map[string]cimdCacheEntry
	// inflight は実行中の fetch を client_id 単位でまとめるための待ち合わせ表。
	inflight map[string]*cimdFetchCall
}

// newCIMDFetcher は allowIP を接続先 IP ポリシーとする cimdFetcher を構築する。
// 本番の構築経路（NewOAuthServer）は常に denyInternalIP を渡す。
func newCIMDFetcher(allowIP func(net.IP) error) *cimdFetcher {
	f := &cimdFetcher{
		allowIP:    allowIP,
		resolver:   net.DefaultResolver,
		now:        time.Now,
		maxEntries: cimdMaxCacheEntries,
		sem:        make(chan struct{}, cimdMaxConcurrentFetches),
		cache:      make(map[string]cimdCacheEntry),
		inflight:   make(map[string]*cimdFetchCall),
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = f.dialContext
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	// 【重要・セキュリティ】CIMD の取得は決してプロキシを経由させない。
	// http.DefaultTransport は Proxy: ProxyFromEnvironment を持ち、Clone() でも引き継がれる。
	// HTTPS_PROXY 等が設定された環境ではプロキシへ dial することになり、
	// dialContext（resolve-then-dial-by-IP）が検査するのはプロキシの IP だけになる。
	// 実際の接続先はプロキシ側で解決・接続されるため IP ポリシーが完全に迂回され、
	// VPC 内の egress プロキシ構成では SSRF（クラウドメタデータ等）が復活してしまう。
	transport.Proxy = nil

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
	u, err := parseCIMDClientID(clientID)
	if err != nil {
		return nil, err
	}
	// キャッシュキーは正規形。fetch と client_id 一致検証は要求された表記のまま行う。
	cacheKey := canonicalCIMDClientID(u)

	if entry, ok := f.lookupCache(cacheKey); ok {
		// ネガティブキャッシュはエラーをそのまま返す(成功に化けさせない)。
		return entry.client, entry.err
	}

	return f.resolveOnce(ctx, clientID, cacheKey)
}

// resolveOnce は同一 client_id への並行呼び出しを 1 回の fetch にまとめて解決する。
// 先着した呼び出しだけが fetch を実行し、後続はその結果を待って共有する。
// client_id は未認証入力なので、1 つの client_id への殺到がそのまま
// 外向きリクエストの本数になることを避ける。inflight の重複排除もキャッシュと
// 同じ正規化キー(cacheKey)で行う。
func (f *cimdFetcher) resolveOnce(ctx context.Context, clientID, cacheKey string) (*ClientData, error) {
	f.mu.Lock()
	if call, ok := f.inflight[cacheKey]; ok {
		f.mu.Unlock()
		select {
		case <-call.done:
			return call.client, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &cimdFetchCall{done: make(chan struct{})}
	f.inflight[cacheKey] = call
	f.mu.Unlock()

	call.client, call.err = f.fetchWithLimit(ctx, clientID, cacheKey)

	f.mu.Lock()
	delete(f.inflight, cacheKey)
	f.mu.Unlock()
	close(call.done)

	return call.client, call.err
}

// fetchWithLimit は同時実行数の上限を守りながら fetch し、結果をキャッシュへ反映する。
// 失敗した場合は短期間のネガティブキャッシュを残したうえでエラーを返す(fail-closed)。
func (f *cimdFetcher) fetchWithLimit(ctx context.Context, clientID, cacheKey string) (*ClientData, error) {
	select {
	case f.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-f.sem }()

	// 順番待ちの間に他の呼び出しがキャッシュを埋めている可能性がある。
	if entry, ok := f.lookupCache(cacheKey); ok {
		return entry.client, entry.err
	}

	client, ttl, err := f.fetch(ctx, clientID)
	if err != nil {
		f.storeCache(cacheKey, cimdCacheEntry{err: err}, cimdNegativeTTL)
		return nil, err
	}
	if ttl > 0 {
		f.storeCache(cacheKey, cimdCacheEntry{client: cloneClientData(client)}, ttl)
	}
	return client, nil
}

// lookupCache は有効期限内のキャッシュを引く。
// 返すエントリの client は防御的コピーで、キャッシュが保持する *ClientData は外へ出さない。
func (f *cimdFetcher) lookupCache(cacheKey string) (cimdCacheEntry, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	entry, ok := f.cache[cacheKey]
	if !ok || !f.now().Before(entry.expiresAt) {
		return cimdCacheEntry{}, false
	}
	entry.client = cloneClientData(entry.client)
	return entry, true
}

// storeCache はキャッシュへ登録する。上限を超える場合は失効済みエントリを掃除し、
// それでも空かないときは期限が最も近いエントリを捨てる。
func (f *cimdFetcher) storeCache(cacheKey string, entry cimdCacheEntry, ttl time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := f.now()
	if _, exists := f.cache[cacheKey]; !exists && len(f.cache) >= f.maxEntries {
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

	entry.expiresAt = now.Add(ttl)
	f.cache[cacheKey] = entry
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

// isCIMDRedirectURI は metadata document の redirect_uri として受理してよい URI かを判定する。
// https スキーム、またはループバックアドレス（ネイティブアプリ向け）のみを許可し、
// それ以外のスキーム（外部ホストへの http、カスタムスキーム等）は拒否する。
//
// 【重要・セキュリティ】metadata document は第三者ホストが配布するため、
// ここで通した URI はそのまま「クライアントが申告した redirect_uri」として扱われる。
// カスタムスキームは端末上の任意アプリに横取りされうるので受け付けない。
func isCIMDRedirectURI(u *url.URL) bool {
	host := u.Hostname()
	isLoopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	switch u.Scheme {
	case "https":
		return true
	case "http":
		return isLoopback
	default:
		return false
	}
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
		if !isCIMDRedirectURI(u) {
			return nil, fmt.Errorf("cimd: redirect_uri %q must be https or a loopback URL", uri)
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
