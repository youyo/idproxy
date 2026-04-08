// Package main は idproxy ライブラリを使った MCP サーバー保護の例です。
// OAuth 2.1 Authorization Server として動作し、Dynamic Client Registration をサポートします。
//
// Auth.New() は Config.OAuth が設定されていれば OAuthServer を自動で初期化します。
//
// 環境変数:
//
//	UPSTREAM_URL       - プロキシ先 MCP サーバー URL（必須）
//	EXTERNAL_URL       - 外部公開 URL（必須）
//	COOKIE_SECRET      - Cookie 暗号化キー、hex エンコード 32 バイト以上（必須）
//	OIDC_ISSUER        - OIDC Issuer URL（必須）
//	OIDC_CLIENT_ID     - OAuth Client ID（必須）
//	OIDC_CLIENT_SECRET - OAuth Client Secret（オプション）
//	PORT               - リッスンポート（デフォルト: 8080）
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

	// JWT 署名用の ECDSA P-256 鍵を生成
	// 本番環境では永続化された鍵を使用すること
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate signing key: %v", err)
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
		OAuth: &idproxy.OAuthConfig{
			SigningKey: signingKey,
			// Dynamic Client Registration を使用するため、
			// 静的な ClientID や AllowedRedirectURIs は設定しない
		},
	}

	// Auth.New() は Config.OAuth が設定されていれば
	// OAuthServer を自動で構築・設定する
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

	log.Printf("idproxy (MCP OAuth AS) listening on :%s, upstream=%s", port, upstreamURL)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("environment variable %s is required", key)
	}
	return v
}
