package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	idproxy "github.com/youyo/idproxy"
	"github.com/youyo/idproxy/store"
)

// parseConfig は環境変数から Config、upstream URL、listenAddr を構築する。
// 必須環境変数が不足している場合はエラーを返す。
func parseConfig() (idproxy.Config, string, string, error) {
	var cfg idproxy.Config
	var errs []string

	// UPSTREAM_URL（必須）
	upstream := os.Getenv("UPSTREAM_URL")
	if upstream == "" {
		errs = append(errs, "UPSTREAM_URL is required")
	}

	// EXTERNAL_URL（必須）
	cfg.ExternalURL = os.Getenv("EXTERNAL_URL")
	if cfg.ExternalURL == "" {
		errs = append(errs, "EXTERNAL_URL is required")
	}

	// COOKIE_SECRET（必須、hex エンコードされた 32 バイト以上）
	cookieSecretHex := os.Getenv("COOKIE_SECRET")
	if cookieSecretHex == "" {
		errs = append(errs, "COOKIE_SECRET is required")
	} else {
		decoded, err := hex.DecodeString(cookieSecretHex)
		if err != nil {
			errs = append(errs, fmt.Sprintf("COOKIE_SECRET: invalid hex: %v", err))
		} else {
			cfg.CookieSecret = decoded
		}
	}

	// OIDC_ISSUER（必須）
	oidcIssuer := os.Getenv("OIDC_ISSUER")
	if oidcIssuer == "" {
		errs = append(errs, "OIDC_ISSUER is required")
	}

	// OIDC_CLIENT_ID（必須）
	oidcClientID := os.Getenv("OIDC_CLIENT_ID")
	if oidcIssuer != "" && oidcClientID == "" {
		errs = append(errs, "OIDC_CLIENT_ID is required")
	}

	// OIDC_CLIENT_SECRET（オプション、ただしプロバイダーが設定される場合は必要）
	oidcClientSecret := os.Getenv("OIDC_CLIENT_SECRET")

	// プロバイダー構築
	if oidcIssuer != "" && oidcClientID != "" {
		issuers := splitTrim(oidcIssuer)
		clientIDs := splitTrim(oidcClientID)
		clientSecrets := splitTrim(oidcClientSecret)

		if len(issuers) != len(clientIDs) || (len(clientSecrets) > 0 && len(issuers) != len(clientSecrets)) {
			errs = append(errs, "OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET must have the same number of comma-separated values")
		} else {
			providerName := os.Getenv("OIDC_PROVIDER_NAME")
			providerNames := splitTrim(providerName)

			for i, issuer := range issuers {
				p := idproxy.OIDCProvider{
					Issuer:   issuer,
					ClientID: clientIDs[i],
				}
				if i < len(clientSecrets) {
					p.ClientSecret = clientSecrets[i]
				}
				if i < len(providerNames) {
					p.Name = providerNames[i]
				}
				cfg.Providers = append(cfg.Providers, p)
			}
		}
	}

	// PATH_PREFIX（オプション）
	cfg.PathPrefix = os.Getenv("PATH_PREFIX")

	// ALLOWED_DOMAINS（オプション、カンマ区切り）
	if v := os.Getenv("ALLOWED_DOMAINS"); v != "" {
		cfg.AllowedDomains = splitTrim(v)
	}

	// ALLOWED_EMAILS（オプション、カンマ区切り）
	if v := os.Getenv("ALLOWED_EMAILS"); v != "" {
		cfg.AllowedEmails = splitTrim(v)
	}

	// PORT（デフォルト: 8080）
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	listenAddr := ":" + port

	// Store（デフォルト: MemoryStore）
	cfg.Store = store.NewMemoryStore()

	// OAUTH_CLIENT_ID / OAUTH_ALLOWED_REDIRECT_URIS（オプション）
	// 注: JWT_SIGNING_KEY_FILE がない場合は OAuth AS は有効化しない
	// ここでは OAuthConfig の ClientID と AllowedRedirectURIs のみ保持
	// SigningKey は JWT_SIGNING_KEY_FILE から読み込む処理が必要だが M18 スコープ外

	if len(errs) > 0 {
		return idproxy.Config{}, "", "", fmt.Errorf("config error: %s", strings.Join(errs, "; "))
	}

	return cfg, upstream, listenAddr, nil
}

// splitTrim はカンマ区切り文字列を分割し、各要素の前後の空白を除去する。
// 空文字列の場合は空スライスを返す。
func splitTrim(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
