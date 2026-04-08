package main

import (
	"context"
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

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, upstream, listenAddr, err := parseConfig()
	if err != nil {
		return err
	}

	logger := slog.Default()
	cfg.Logger = logger

	// Auth の初期化
	ctx := context.Background()
	auth, err := idproxy.New(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize auth: %w", err)
	}

	// リバースプロキシの設定
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

	// グレースフルシャットダウン
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

// newReverseProxy は upstream URL へのリバースプロキシを構築する。
// FlushInterval: -1 で SSE ストリーミングをパススルーする。
func newReverseProxy(upstream string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = -1 // SSE ストリーミング対応: レスポンスを即座にフラッシュ

	return proxy, nil
}

// healthzHandler はヘルスチェックエンドポイント。
func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}
