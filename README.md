**English** | [日本語](README_ja.md)

# idproxy

OIDC authentication reverse proxy + MCP OAuth 2.1 Authorization Server.

idproxy sits in front of any HTTP backend and transparently provides OIDC browser authentication and OAuth 2.1 Bearer Token validation. It also acts as an OAuth 2.1 Authorization Server to protect MCP (Model Context Protocol) servers, with support for Dynamic Client Registration (RFC 7591).

## Features

- OIDC-based browser authentication (Google, Microsoft Entra ID, etc.)
- OAuth 2.1 Authorization Server (PKCE required, Bearer Token issuance, refresh_token rotation)
- Dynamic Client Registration (RFC 7591)
- SSE (Server-Sent Events) transparent proxy
- Optimized for protecting MCP servers
- Zero-dependency in-memory session store (replaceable for production)

## Installation

### Go

```bash
go install github.com/youyo/idproxy/cmd/idproxy@latest
```

### Docker

```bash
docker pull ghcr.io/youyo/idproxy:latest
```

## Quick Start

### Configure and run

```bash
export UPSTREAM_URL=http://localhost:3000
export EXTERNAL_URL=https://mcp-auth.example.com
export COOKIE_SECRET=$(openssl rand -hex 32)
export OIDC_ISSUER=https://accounts.google.com
export OIDC_CLIENT_ID=your-client-id
export OIDC_CLIENT_SECRET=your-client-secret

idproxy
```

### Docker Compose

```yaml
version: "3.8"
services:
  idproxy:
    image: ghcr.io/youyo/idproxy:latest
    ports:
      - "8080:8080"
    environment:
      UPSTREAM_URL: http://backend:3000
      EXTERNAL_URL: https://mcp-auth.example.com
      COOKIE_SECRET: "${COOKIE_SECRET}"
      OIDC_ISSUER: https://accounts.google.com
      OIDC_CLIENT_ID: "${OIDC_CLIENT_ID}"
      OIDC_CLIENT_SECRET: "${OIDC_CLIENT_SECRET}"
    depends_on:
      - backend

  backend:
    image: your-backend:latest
    expose:
      - "3000"
```

## Environment Variables

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `UPSTREAM_URL` | Backend URL to proxy to | `http://localhost:3000` |
| `EXTERNAL_URL` | External URL of this service | `https://mcp-auth.example.com` |
| `COOKIE_SECRET` | Cookie encryption key (hex-encoded, 32+ bytes) | Generate with `openssl rand -hex 32` |
| `OIDC_ISSUER` | OIDC Issuer URL (comma-separated for multiple) | `https://accounts.google.com` |
| `OIDC_CLIENT_ID` | OAuth Client ID (comma-separated for multiple) | `your-client-id` |

### Optional

| Variable | Description | Default |
|----------|-------------|---------|
| `OIDC_CLIENT_SECRET` | OAuth Client Secret (comma-separated for multiple) | none |
| `OIDC_PROVIDER_NAME` | Provider display name (comma-separated for multiple) | Auto-generated from Issuer |
| `ALLOWED_DOMAINS` | Allowed email domains (comma-separated) | no restriction |
| `ALLOWED_EMAILS` | Allowed email addresses (comma-separated) | no restriction |
| `PATH_PREFIX` | OAuth 2.1 AS endpoint path prefix | none |
| `PORT` | Listen port | `8080` |

## Provider Setup

| Provider | `OIDC_ISSUER` | Setup Guide |
|----------|--------------|-------------|
| Google | `https://accounts.google.com` | [OpenID Connect — Google Identity](https://developers.google.com/identity/openid-connect/openid-connect) |
| Microsoft Entra ID | `https://login.microsoftonline.com/{tenant-id}/v2.0` | [Register an application — Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app) |

When registering idproxy as a client in your OIDC provider, set the redirect URI to:

```
{EXTERNAL_URL}/auth/callback
```

## Library Usage

idproxy can also be used as a Go library.

### Basic Reverse Proxy

```go
package main

import (
	"context"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	idproxy "github.com/youyo/idproxy"
	"github.com/youyo/idproxy/store"
)

func main() {
	cfg := idproxy.Config{
		Providers: []idproxy.OIDCProvider{
			{
				Issuer:       "https://accounts.google.com",
				ClientID:     "your-client-id",
				ClientSecret: "your-client-secret",
			},
		},
		ExternalURL:  "https://mcp-auth.example.com",
		CookieSecret: []byte("32-byte-secret-key-here-1234567"),
		Store:        store.NewMemoryStore(),
	}

	auth, err := idproxy.New(context.Background(), cfg)
	if err != nil {
		log.Fatal(err)
	}

	upstream, _ := url.Parse("http://localhost:3000")
	proxy := httputil.NewSingleHostReverseProxy(upstream)

	http.Handle("/", auth.Wrap(proxy))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### MCP Server Protection (OAuth 2.1 AS)

Setting `Config.OAuth` enables automatic OAuthServer initialization in `Auth.New()`.

```go
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	idproxy "github.com/youyo/idproxy"
	"github.com/youyo/idproxy/store"
)

func main() {
	// Generate ECDSA P-256 key for JWT signing
	// Use a persisted key in production
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	cfg := idproxy.Config{
		Providers: []idproxy.OIDCProvider{
			{
				Issuer:       "https://accounts.google.com",
				ClientID:     "your-client-id",
				ClientSecret: "your-client-secret",
			},
		},
		ExternalURL:     "https://mcp-auth.example.com",
		CookieSecret:    []byte("32-byte-secret-key-here-1234567"),
		Store:           store.NewMemoryStore(),
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 30 * 24 * time.Hour, // 30 days
		OAuth: &idproxy.OAuthConfig{
			SigningKey: signingKey,
		},
	}

	// OAuthServer is automatically initialized when Config.OAuth is set
	auth, err := idproxy.New(context.Background(), cfg)
	if err != nil {
		log.Fatal(err)
	}

	upstream, _ := url.Parse("http://localhost:3000")
	proxy := httputil.NewSingleHostReverseProxy(upstream)

	http.Handle("/", auth.Wrap(proxy))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## DynamoDB Store

For multi-instance deployments (e.g., AWS Lambda with multiple concurrent containers), use `DynamoDBStore` to share state across instances.

### Usage

```go
import "github.com/youyo/idproxy/store"

s, err := store.NewDynamoDBStore("my-idproxy-table", "ap-northeast-1")
if err != nil {
    log.Fatal(err)
}
defer s.Close()

cfg := idproxy.Config{
    Store: s,
    // ...
}
```

### Create DynamoDB Table

```bash
aws dynamodb create-table \
  --table-name my-idproxy-table \
  --attribute-definitions AttributeName=pk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region ap-northeast-1

# Enable TTL on the "ttl" attribute
aws dynamodb update-time-to-live \
  --table-name my-idproxy-table \
  --time-to-live-specification "Enabled=true,AttributeName=ttl" \
  --region ap-northeast-1
```

### IAM Permissions (Minimum)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:DeleteItem"
      ],
      "Resource": "arn:aws:dynamodb:ap-northeast-1:123456789012:table/my-idproxy-table"
    }
  ]
}
```

> **Security**: The `data` attribute contains sensitive information (session data, access tokens). Enable [DynamoDB server-side encryption with AWS KMS (SSE-KMS)](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html) for production use.

> **Note**: `Cleanup()` is a no-op — expired items are removed automatically by DynamoDB TTL. DynamoDB TTL may have up to 48 hours of lag; `DynamoDBStore` compensates by checking the `ttl` attribute on every `Get` and returning `nil` for expired items.

## License

[MIT License](LICENSE)
