// Package main は idproxy ライブラリを使った基本的なリバースプロキシの例です。
//
// 環境変数:
//
//	UPSTREAM_URL    - プロキシ先 URL（必須）
//	EXTERNAL_URL    - 外部公開 URL（必須）
//	COOKIE_SECRET   - Cookie 暗号化キー、hex エンコード 32 バイト以上（必須）
//	OIDC_ISSUER     - OIDC Issuer URL（必須）
//	OIDC_CLIENT_ID  - OAuth Client ID（必須）
//	OIDC_CLIENT_SECRET - OAuth Client Secret（オプション）
//	PORT            - リッスンポート（デフォルト: 8080）
package main

import (
	"context"
	"encoding/hex"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	idproxy "github.com/youyo/idproxy"
	"github.com/youyo/idproxy/store"
)

func main() {
	upstreamURL := mustEnv("UPSTREAM_URL")
	externalURL := mustEnv("EXTERNAL_URL")
	cookieSecretHex := mustEnv("COOKIE_SECRET")
	oidcIssuer := mustEnv("OIDC_ISSUER")
	oidcClientID := mustEnv("OIDC_CLIENT_ID")
	oidcClientSecret := os.Getenv("OIDC_CLIENT_SECRET")

	cookieSecret, err := hex.DecodeString(cookieSecretHex)
	if err != nil {
		log.Fatalf("COOKIE_SECRET: invalid hex: %v", err)
	}

	cfg := idproxy.Config{
		Providers: []idproxy.OIDCProvider{
			{
				Issuer:       oidcIssuer,
				ClientID:     oidcClientID,
				ClientSecret: oidcClientSecret,
			},
		},
		ExternalURL:  externalURL,
		CookieSecret: cookieSecret,
		Store:        store.NewMemoryStore(),
	}

	auth, err := idproxy.New(context.Background(), cfg)
	if err != nil {
		log.Fatalf("idproxy.New: %v", err)
	}

	upstream, err := url.Parse(upstreamURL)
	if err != nil {
		log.Fatalf("invalid UPSTREAM_URL: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	mux.Handle("/", auth.Wrap(proxy))

	log.Printf("idproxy listening on :%s, upstream=%s", port, upstreamURL)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("environment variable %s is required", key)
	}
	return v
}
