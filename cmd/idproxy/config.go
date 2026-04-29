package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	idproxy "github.com/youyo/idproxy"
	"github.com/youyo/idproxy/store"
	redisstore "github.com/youyo/idproxy/store/redis"
	sqlitestore "github.com/youyo/idproxy/store/sqlite"
)

// parseConfig builds Config, upstream URL, and listenAddr from environment variables.
// Returns an error if required environment variables are missing.
func parseConfig() (idproxy.Config, string, string, error) {
	var cfg idproxy.Config
	var errs []string

	// UPSTREAM_URL (required)
	upstream := os.Getenv("UPSTREAM_URL")
	if upstream == "" {
		errs = append(errs, "UPSTREAM_URL is required")
	}

	// EXTERNAL_URL (required)
	cfg.ExternalURL = os.Getenv("EXTERNAL_URL")
	if cfg.ExternalURL == "" {
		errs = append(errs, "EXTERNAL_URL is required")
	}

	// COOKIE_SECRET (required, hex-encoded 32+ bytes)
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

	// OIDC_ISSUER (required)
	oidcIssuer := os.Getenv("OIDC_ISSUER")
	if oidcIssuer == "" {
		errs = append(errs, "OIDC_ISSUER is required")
	}

	// OIDC_CLIENT_ID (required)
	oidcClientID := os.Getenv("OIDC_CLIENT_ID")
	if oidcIssuer != "" && oidcClientID == "" {
		errs = append(errs, "OIDC_CLIENT_ID is required")
	}

	// OIDC_CLIENT_SECRET (optional)
	oidcClientSecret := os.Getenv("OIDC_CLIENT_SECRET")

	// Build providers
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

	// PATH_PREFIX (optional)
	cfg.PathPrefix = os.Getenv("PATH_PREFIX")

	// ALLOWED_DOMAINS (optional, comma-separated)
	if v := os.Getenv("ALLOWED_DOMAINS"); v != "" {
		cfg.AllowedDomains = splitTrim(v)
	}

	// ALLOWED_EMAILS (optional, comma-separated)
	if v := os.Getenv("ALLOWED_EMAILS"); v != "" {
		cfg.AllowedEmails = splitTrim(v)
	}

	// PORT (default: 8080)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	listenAddr := ":" + port

	// Store (STORE_BACKEND で切替。デフォルトは memory)
	s, storeErr := loadStore()
	if storeErr != nil {
		errs = append(errs, storeErr.Error())
	} else {
		cfg.Store = s
	}

	// OAUTH_CLIENT_ID / OAUTH_ALLOWED_REDIRECT_URIS (optional)
	// Note: OAuth AS is not enabled without JWT_SIGNING_KEY_FILE
	// Only ClientID and AllowedRedirectURIs are stored here
	// SigningKey must be loaded from JWT_SIGNING_KEY_FILE (M18 scope)

	if len(errs) > 0 {
		return idproxy.Config{}, "", "", fmt.Errorf("config error: %s", strings.Join(errs, "; "))
	}

	return cfg, upstream, listenAddr, nil
}

// loadStore は STORE_BACKEND 環境変数を見て idproxy.Store 実装を生成する。
// サポートする値: memory(default) / dynamodb / sqlite / redis
func loadStore() (idproxy.Store, error) {
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("STORE_BACKEND")))
	if backend == "" {
		backend = "memory"
	}
	switch backend {
	case "memory":
		return store.NewMemoryStore(), nil

	case "dynamodb":
		table := os.Getenv("DYNAMODB_TABLE_NAME")
		region := os.Getenv("AWS_REGION")
		if table == "" {
			return nil, fmt.Errorf("STORE_BACKEND=dynamodb requires DYNAMODB_TABLE_NAME")
		}
		if region == "" {
			return nil, fmt.Errorf("STORE_BACKEND=dynamodb requires AWS_REGION")
		}
		return store.NewDynamoDBStore(table, region)

	case "sqlite":
		path := os.Getenv("SQLITE_PATH")
		if path == "" {
			path = ":memory:"
		}
		return sqlitestore.New(path)

	case "redis":
		addr := os.Getenv("REDIS_ADDR")
		if addr == "" {
			return nil, fmt.Errorf("STORE_BACKEND=redis requires REDIS_ADDR")
		}
		dbNum := 0
		if v := os.Getenv("REDIS_DB"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("REDIS_DB: %w", err)
			}
			if n < 0 {
				return nil, fmt.Errorf("REDIS_DB must be non-negative, got %d", n)
			}
			dbNum = n
		}
		tls := strings.EqualFold(os.Getenv("REDIS_TLS"), "true")
		return redisstore.New(redisstore.Options{
			Addr:      addr,
			Password:  os.Getenv("REDIS_PASSWORD"),
			DB:        dbNum,
			TLS:       tls,
			KeyPrefix: os.Getenv("REDIS_KEY_PREFIX"),
		})

	default:
		return nil, fmt.Errorf("STORE_BACKEND %q not supported (allowed: memory, dynamodb, sqlite, redis)", backend)
	}
}

// splitTrim splits a comma-separated string and trims whitespace from each element.
// Returns nil for an empty string.
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

// printUsage prints the usage message for the idproxy command.
func printUsage() {
	w := flag.CommandLine.Output()
	_, _ = fmt.Fprint(w, `Usage: idproxy

OIDC authentication reverse proxy and MCP OAuth 2.1 Authorization Server.

Environment Variables:

  Required:
    UPSTREAM_URL          Backend URL to proxy to (e.g. http://localhost:3000)
    EXTERNAL_URL          External URL of this service (e.g. https://proxy.example.com)
    COOKIE_SECRET         Cookie encryption key, hex-encoded 32+ bytes
                          Generate with: openssl rand -hex 32
    OIDC_ISSUER           OIDC Issuer URL (comma-separated for multiple providers)
    OIDC_CLIENT_ID        OAuth Client ID (comma-separated for multiple providers)

  Optional:
    OIDC_CLIENT_SECRET    OAuth Client Secret (comma-separated for multiple providers)
    OIDC_PROVIDER_NAME    Provider display name (comma-separated for multiple providers)
    ALLOWED_DOMAINS       Allowed email domains (comma-separated)
    ALLOWED_EMAILS        Allowed email addresses (comma-separated)
    PATH_PREFIX           OAuth 2.1 AS endpoint path prefix
    PORT                  Listen port (default: 8080)

  Store backend (optional, default: memory):
    STORE_BACKEND         Store backend: memory (default) | dynamodb | sqlite | redis

    For STORE_BACKEND=dynamodb:
      DYNAMODB_TABLE_NAME   DynamoDB table name (required)
      AWS_REGION            AWS region (required, e.g. us-east-1)

    For STORE_BACKEND=sqlite:
      SQLITE_PATH           SQLite database file path (default: :memory:)

    For STORE_BACKEND=redis:
      REDIS_ADDR            Redis host:port (required, e.g. localhost:6379)
      REDIS_PASSWORD        Redis password (optional)
      REDIS_DB              Redis DB number (optional, default: 0)
      REDIS_TLS             "true" to enable TLS (optional)
      REDIS_KEY_PREFIX      Key prefix (optional, e.g. "idproxy:")
`)
}
