package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
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

	cfg, upstream, listenAddr, err := parseConfig()
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
	proxy, err := newReverseProxy(upstream)
	if err != nil {
		return fmt.Errorf("failed to create reverse proxy: %w", err)
	}

	// ルーティング
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthzHandler)
	mux.Handle("/", auth.Wrap(proxy))

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("starting server", "addr", listenAddr, "upstream", upstream)
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

// newReverseProxy は upstream URL へのリバースプロキシを生成する。
// FlushInterval: -1 を設定し、SSE 透過を有効にする。
func newReverseProxy(upstream string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = -1 // SSE 透過のため即時 flush

	return proxy, nil
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
