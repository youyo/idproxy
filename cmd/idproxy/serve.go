package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	idproxy "github.com/youyo/idproxy"
)

// runServe は従来の "idproxy"（サブコマンドなし）相当のサーバー起動処理。
// main.go のサブコマンドルーターから "serve" または引数なしのケースで呼ばれる。
// flag は CommandLine（グローバル）を引き続き使用する。これは TestPrintUsage が
// flag.CommandLine.SetOutput を経由してテストする既存仕様を壊さないため。
func runServe() error {
	flag.Usage = printUsage
	flag.Parse()

	cfg, pc, err := parseConfig()
	if err != nil {
		return err
	}

	logger := slog.Default()
	cfg.Logger = logger

	// Auth を初期化
	ctx := context.Background()
	auth, err := idproxy.New(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize auth: %w", err)
	}

	// リバースプロキシ
	proxy, err := newReverseProxy(pc.upstream, pc.upstreamAuthToken)
	if err != nil {
		return fmt.Errorf("failed to create reverse proxy: %w", err)
	}

	// ルーティング
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthzHandler)
	mux.Handle("/", auth.Wrap(proxy))

	srv := &http.Server{
		Addr:    pc.listenAddr,
		Handler: mux,
	}

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("starting server", "addr", pc.listenAddr, "upstream", pc.upstream)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down server")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return srv.Shutdown(shutdownCtx)
}

// parseUpstream は UPSTREAM_URL を解釈し、プロキシ先 URL と、Unix domain socket
// 指定（unix:///path/to/backend.sock）のときはそのソケットパスを返す。
// TCP 指定のときソケットパスは空文字列になる。
//
// unix:// のときの target はダミーの http://unix を返す。Host が空のままだと
// Rewrite の SetURL が壊れるため、必ずホスト名を置く必要がある。実際の接続先は
// Transport.DialContext がソケットパスから決めるため、この値は使われない。
func parseUpstream(raw string) (*url.URL, string, error) {
	target, err := url.Parse(raw)
	if err != nil {
		return nil, "", fmt.Errorf("invalid upstream URL: %w", err)
	}
	if target.Scheme != "unix" {
		return target, "", nil
	}

	// unix://relative/backend.sock は Host が "relative" になる（相対パス指定）。
	if target.Host != "" {
		return nil, "", fmt.Errorf("invalid upstream URL: unix:// requires an absolute socket path, got relative %q (use unix:///path/to/backend.sock)", target.Host+target.Path)
	}
	socketPath := target.Path
	if socketPath == "" {
		return nil, "", fmt.Errorf("invalid upstream URL: unix:// requires a socket path (use unix:///path/to/backend.sock)")
	}
	if !filepath.IsAbs(socketPath) {
		return nil, "", fmt.Errorf("invalid upstream URL: unix:// socket path must be absolute, got %q", socketPath)
	}

	return &url.URL{Scheme: "http", Host: "unix"}, socketPath, nil
}

// newReverseProxy は upstream URL へのリバースプロキシを生成する。
// FlushInterval: -1 を設定し、SSE 透過を有効にする。
//
// upstream が unix:// の場合は Transport.DialContext を UDS dial へ差し替える。
// Rewrite は TCP と共有し、UDS 用に分岐させない（pr.Out.Host = pr.In.Host に
// より、ダミーの "unix" ホスト名は upstream の Host ヘッダーに現れない）。
//
// authToken が空でない場合、upstream へのリクエストに
// Authorization: Bearer <authToken> を注入する。クライアント由来の
// Authorization（idproxy 自身の Bearer 検証済み）は upstream へ漏らさないよう
// 注入前に削除する。Director ではなく Rewrite フックを使うのは、Director は
// hop-by-hop ヘッダー除去の前に呼ばれるため、クライアントが
// Connection: Authorization を送ると注入したヘッダーごと落ちるため
// （golang/go#50580）。あわせてセッション Cookie も除去する
// （stripSessionCookie）。
//
// あわせて ID 系ヘッダー（identityHeaders）はクライアント由来の値を必ず削除し、
// 認証済みなら idproxy の認証結果で付け直す（rewriteIdentityHeaders）。
func newReverseProxy(upstream, authToken string) (*httputil.ReverseProxy, error) {
	target, socketPath, err := parseUpstream(upstream)
	if err != nil {
		return nil, err
	}
	proxy := &httputil.ReverseProxy{
		FlushInterval: -1, // SSE 透過のため即時 flush
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			// SetURL は Out.Host を空にするため、inbound の Host を明示的に保持する。
			pr.Out.Host = pr.In.Host
			restoreForwardedHeaders(pr)
			rewriteIdentityHeaders(pr)

			if authToken != "" {
				pr.Out.Header.Del("Authorization")
				pr.Out.Header.Set("Authorization", "Bearer "+authToken)
				stripSessionCookie(pr.Out)
			}
		},
	}

	if socketPath != "" {
		// 既定 Transport の Clone をベースにするのは、タイムアウトや
		// コネクション上限といった既定値を落とさないため。
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		}
		proxy.Transport = transport
	}

	return proxy, nil
}

// restoreForwardedHeaders は Rewrite フック使用時に ReverseProxy が Out から
// 削除する転送系ヘッダーを、Director 時代と同じ状態へ戻す。
// SetXForwarded は使わない（X-Forwarded-Proto/Host を無条件に上書きするため、
// TLS 終端エッジが付けた X-Forwarded-Proto: https を http へ書き換えてしまう）。
// X-Forwarded-For のみ inbound の値へクライアント IP を追記する。
func restoreForwardedHeaders(pr *httputil.ProxyRequest) {
	for _, name := range []string{"Forwarded", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-For"} {
		// Director 時代は hop-by-hop 除去の対象になったヘッダーは復元しない。
		if connectionListsHeader(pr.In, name) {
			continue
		}
		if v, ok := pr.In.Header[name]; ok {
			pr.Out.Header[name] = slices.Clone(v)
		}
	}

	clientIP, _, err := net.SplitHostPort(pr.In.RemoteAddr)
	if err != nil {
		return
	}
	if prior := pr.Out.Header["X-Forwarded-For"]; len(prior) > 0 {
		clientIP = strings.Join(prior, ", ") + ", " + clientIP
	}
	pr.Out.Header.Set("X-Forwarded-For", clientIP)
}

// stripSessionCookie は idproxy のセッション Cookie（idproxy.SessionCookieName）を
// upstream へのリクエストから取り除く。
//
// Cookie は hop-by-hop ヘッダーではないため、Authorization を差し替えても
// ブラウザ認証時のセッション Cookie はそのまま upstream に届く。この Cookie は
// EXTERNAL_URL に対してユーザーとして振る舞える完全な資格情報であり、
// /authorize がセッション認証を受け付けるため OAuth code の発行まで可能になる。
// UPSTREAM_AUTH_TOKEN を設定した構成の「upstream にクライアントの資格情報を
// 渡さない」という前提を破る。
//
// upstream 自身の Cookie を必要とする構成があるため、Cookie ヘッダー全体では
// なく該当 Cookie だけを外し、残りが空になったときだけヘッダーを削除する。
// セッション Cookie が無いリクエストではヘッダーに一切触れない。
func stripSessionCookie(out *http.Request) {
	cookies := out.Cookies()
	kept := make([]string, 0, len(cookies))
	found := false
	for _, c := range cookies {
		if c.Name == idproxy.SessionCookieName {
			found = true
			continue
		}
		kept = append(kept, c.Name+"="+c.Value)
	}
	if !found {
		return
	}
	if len(kept) == 0 {
		out.Header.Del("Cookie")
		return
	}
	out.Header.Set("Cookie", strings.Join(kept, "; "))
}

// identityHeaders は「前段のプロキシが認証結果として付けた」と upstream が
// 解釈しうる ID 系ヘッダーの denylist。oauth2-proxy 系（X-Forwarded-*・
// X-Auth-Request-*）と nginx/Apache 系（X-Remote-*）の慣習を網羅する。
//
// UPSTREAM_AUTH_TOKEN を設定した構成では、upstream は共有トークンによって
// 「このリクエストは idproxy から来た」と判断できてしまうため、クライアントが
// 自分で付けた ID ヘッダーをそのまま素通しすると権限昇格（confused deputy）に
// なる。認証の有無にかかわらず無条件に削除する。
var identityHeaders = []string{
	"X-Forwarded-User",
	"X-Forwarded-Email",
	"X-Forwarded-Preferred-Username",
	"X-Forwarded-Groups",
	"X-Auth-Request-User",
	"X-Auth-Request-Email",
	"X-Auth-Request-Groups",
	"X-Auth-Request-Preferred-Username",
	"X-Remote-User",
	"X-Remote-Email",
	"X-Remote-Groups",
	"X-Authenticated-User",
	"X-User",
	"X-Email",
}

// rewriteIdentityHeaders はクライアント由来の ID 系ヘッダーをすべて削除し、
// 認証済みの場合のみ idproxy 自身の認証結果を X-Forwarded-User（sub）と
// X-Forwarded-Email として付け直す。これにより upstream は「idproxy が付けた
// ID ヘッダーだけが存在する」という単純な前提を置ける。
//
// 認証済みユーザーは Auth.Wrap がリクエストコンテキストへ注入する。
// ReverseProxy は pr.In に元のリクエストをそのまま持たせるため、
// pr.In.Context() から UserFromContext で取得できる。
// 未認証パス（/healthz 等）では何もセットしない。
func rewriteIdentityHeaders(pr *httputil.ProxyRequest) {
	// Header.Del は正規化を行うため、map の直接操作ではなく必ず Del を使う。
	for _, name := range identityHeaders {
		pr.Out.Header.Del(name)
	}

	user := idproxy.UserFromContext(pr.In.Context())
	if user == nil {
		return
	}
	if user.Subject != "" {
		pr.Out.Header.Set("X-Forwarded-User", user.Subject)
	}
	if user.Email != "" {
		pr.Out.Header.Set("X-Forwarded-Email", user.Email)
	}
}

// connectionListsHeader は Connection ヘッダーが name を hop-by-hop として
// 列挙しているかを判定する。
func connectionListsHeader(r *http.Request, name string) bool {
	for _, v := range r.Header["Connection"] {
		for _, token := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), name) {
				return true
			}
		}
	}
	return false
}

// healthzHandler はヘルスチェックエンドポイント。
func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "ok")
}

// printRootUsage はサブコマンドルーターのトップレベル usage を出力する。
func printRootUsage(w *os.File) {
	_, _ = fmt.Fprint(w, `Usage: idproxy [command] [flags]

Commands:
  serve            OIDC 認証リバースプロキシを起動する（デフォルト）
  setup entra-id   Entra ID のアプリ登録を自動化する

Run "idproxy <command> --help" for command-specific help.
For 'serve' (default), run "idproxy --help" to see environment variables.
`)
}
