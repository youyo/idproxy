**English** | [日本語](README_ja.md)

# idproxy

OIDC authentication reverse proxy + MCP OAuth 2.1 Authorization Server.

idproxy sits in front of any HTTP backend and transparently provides OIDC browser authentication and OAuth 2.1 Bearer Token validation. It also acts as an OAuth 2.1 Authorization Server to protect MCP (Model Context Protocol) servers, with support for Dynamic Client Registration (RFC 7591) and Client ID Metadata Documents (CIMD).

## Features

- OIDC-based browser authentication (Google, Microsoft Entra ID, etc.)
- OAuth 2.1 Authorization Server (PKCE required, Bearer Token issuance, refresh_token rotation)
- Dynamic Client Registration (RFC 7591) and Client ID Metadata Documents (CIMD, MCP spec `2026-07-28`)
- Protected Resource Metadata (RFC 9728) and `WWW-Authenticate: resource_metadata=...`
- `iss` parameter on the authorization response (RFC 9207)
- SSE (Server-Sent Events) transparent proxy, and stateless Streamable HTTP transparency for POST-response long-lived streams
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
| `UPSTREAM_URL` | Backend URL to proxy to. Also accepts a Unix domain socket as `unix:///absolute/path/to/backend.sock` | `http://localhost:3000` or `unix:///run/backend.sock` |
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
| `UPSTREAM_AUTH_TOKEN` | Token injected as `Authorization: Bearer <value>` on every upstream request; the client's own `Authorization` header is removed before injection (never forwarded to upstream). **If unset, the client's `Authorization` header is forwarded to upstream unchanged** — this is the default behavior and does not change existing deployments. | none |

## Provider Setup

| Provider | `OIDC_ISSUER` |
|----------|--------------|
| Microsoft Entra ID | `https://login.microsoftonline.com/{tenant-id}/v2.0` |
| Google | `https://accounts.google.com` |
| Amazon Cognito | `https://cognito-idp.{region}.amazonaws.com/{user-pool-id}` |

When registering idproxy as a client in your OIDC provider, set the redirect URI to:

```
{EXTERNAL_URL}/callback
```

### Automated Setup with `idproxy setup entra-id` (Recommended)

Instead of configuring Entra ID manually through the Azure Portal, you can use the built-in setup command:

**Prerequisites**

- [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) installed (`brew install azure-cli` on macOS)
- Logged in to Azure CLI:

```bash
az login
# If running in a headless environment (no browser):
az login --use-device-code
```

**Run the setup command**

```bash
idproxy setup entra-id \
  --instance-name my-idproxy \
  --external-url https://proxy.example.com
```

The command will:
1. Create (or reuse) an Entra ID app registration named `idproxy-{instance-name}`
2. Generate a client secret
3. Register `{external-url}/callback` as a redirect URI
4. Print the environment variables to set

> If `PATH_PREFIX` is configured, pass `--path-prefix /auth` to generate the correct callback URL.

> To use a custom app name prefix (instead of `idproxy-`), add `--name-prefix "my-company-"`.

**Non-interactive mode** (for CI/CD):

```bash
idproxy setup entra-id \
  --instance-name my-idproxy \
  --external-url https://proxy.example.com \
  --non-interactive
```

The manual steps below describe the equivalent portal workflow if you prefer to configure Entra ID by hand.

### Microsoft Entra ID

#### 1. Register an application

[Azure Portal](https://portal.azure.com) → **Microsoft Entra ID** → **App registrations** → **New registration**

- **Supported account types**: *Accounts in this organizational directory only*
- **Redirect URI**: set after your deployment URL is known (see below)

From the **Overview** page, collect:
- **Application (client) ID** → `OIDC_CLIENT_ID`
- **Directory (tenant) ID** → use in `OIDC_ISSUER`: `https://login.microsoftonline.com/{tenant-id}/v2.0`

#### 2. Create a client secret

**Certificates & secrets** → **Client secrets** → **New client secret** → copy the **Value** immediately.

This is `OIDC_CLIENT_SECRET`.

#### 3. Add API permissions

**API permissions** → **Add a permission** → **Microsoft Graph** → **Delegated permissions** → add:

- `openid`
- `email`
- `profile`

Then click **Grant admin consent** to avoid per-user consent prompts.

#### 4. Add optional claims to the ID token

**Token configuration** → **Add optional claim** → **Token type: ID** → check **`email`** → **Add**.

> `name` (display name) is included automatically with the `profile` scope. `family_name` and `given_name` are not required.

#### 5. Set the redirect URI

**Authentication** → **Add a platform** → **Web** → set:

```
{EXTERNAL_URL}/callback
```

> If `PATH_PREFIX` is set (e.g. `PATH_PREFIX=/auth`), append the prefix: `{EXTERNAL_URL}/auth/callback`.

### Amazon Cognito

Request scopes `openid email profile` on the App Client. Cognito ID tokens may omit the `name` claim depending on user pool configuration; idproxy automatically falls back to `cognito:username` (and then `preferred_username`) for the user's display name.

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

### Post-Login Redirect Behavior

After authentication, idproxy redirects users back to the URL they originally
requested. The destination is chosen in this order:

1. The `redirect_to` query parameter passed to `/login`, if supplied.
2. `Config.DefaultPostLoginPath`, if set (e.g. `"/dashboard"`).
3. `"/"` (legacy default).

If your application doesn't mount a handler at `"/"`, set
`DefaultPostLoginPath` to point at a real route, or use the
`OnAuthenticated` hook (below). Without one of these, a fresh login lands
on a 404. (See [kintone#5](https://github.com/youyo/kintone/issues/5) for
the bug this section prevents.)

#### `Config.OnAuthenticated` hook

`OnAuthenticated` runs once, right after the session cookie is issued.
Return values control the next step:

| `handled` | `redirectTo` | Behavior                                                    |
| --------- | ------------ | ----------------------------------------------------------- |
| `true`    | `""`         | Hook already wrote the response; idproxy does nothing.      |
| `true`    | non-empty    | `redirectTo` is **ignored** (hook is considered authoritative). |
| `false`   | non-empty    | idproxy validates `redirectTo` and redirects (302).         |
| `false`   | `""`         | Fallback to the original `redirect_to` or `DefaultPostLoginPath`. |

```go
cfg := idproxy.Config{
    // ...
    DefaultPostLoginPath: "/dashboard",
    OnAuthenticated: func(w http.ResponseWriter, r *http.Request, user *idproxy.User) (string, bool) {
        log.Printf("user %q logged in", user.Email)
        return "", false // use the default redirect chain
    },
}
```

Panic inside the hook is recovered and surfaces as `500`. If you return
`handled=false` but already wrote to the `ResponseWriter`, idproxy logs a
warning and skips its own redirect.

#### Securing `redirect_to` with `StrictPostLoginRedirectValidator`

By default idproxy accepts any `redirect_to` value (legacy behavior). To
turn on the strict open-redirect validator, opt in:

```go
cfg.UseStrictPostLoginRedirectValidator()
```

This rejects `javascript:`, `data:`, protocol-relative (`//evil`),
non-NFKC, backslash, and control-character inputs. Allowed:

- Relative paths starting with `/` (but not `//`).
- HTTPS URLs whose host equals `Config.ExternalURL`'s host
  (same-origin absolute redirect).

The validator runs at every redirect entry point:
`LoginHandler`, `SelectionHandler`, `Auth.Wrap`'s unauthenticated browser
path, `OAuthServer.redirectToLogin`, **and** the `redirectTo` returned by
the `OnAuthenticated` hook. Rejections produce `400` (for user input) or
`500` (for hook output).

#### Cascade OAuth pattern

The `OnAuthenticated` hook is how idproxy applications layer a **second
OAuth flow** (Slack / Backlog / kintone) on top of OIDC login. See
[`examples/cascade-oauth`](examples/cascade-oauth) for a minimal
walkthrough and [`docs/cascade-oauth-pattern.md`](docs/cascade-oauth-pattern.md)
for state management, token persistence, and failure-mode discussion.

#### Migration: from middleware pattern to `OnAuthenticated`

Many apps historically wrap their own middleware around `Auth.Wrap` to
enforce cascade OAuth on every request. The hook lets you do the same in
one place, at the right time:

```go
// Before — runs on every request, easy to miss adding around new mounts.
http.ListenAndServe(":8080", MyOAuthMiddleware(tokenStore, auth.Wrap(mux)))

// After — runs once, right after login, registered with Config.
cfg.OnAuthenticated = func(w http.ResponseWriter, r *http.Request, user *idproxy.User) (string, bool) {
    if !tokenStore.HasToken(user.Email) {
        return "/oauth/external/start?return_to=" + r.URL.Query().Get("redirect_to"), false
    }
    return "", false
}
http.ListenAndServe(":8080", auth.Wrap(mux))
```

Real-world adoption:
[logvalet](https://github.com/youyo/logvalet) — Backlog MCP server.

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

When `Config.OAuth` is set, idproxy also serves:

- `GET /.well-known/oauth-protected-resource` — Protected Resource Metadata (RFC 9728), independent of `PATH_PREFIX` since the `resource` identifier (`ExternalURL`) has no path component. Every `401` response (missing/invalid Bearer token, or an unauthenticated API request) carries `WWW-Authenticate: Bearer resource_metadata="<ExternalURL>/.well-known/oauth-protected-resource", ...` so MCP clients can discover it per the 401 → PRM → AS metadata sequence.
- The authorization response redirect includes `iss=<ExternalURL>` alongside `code` and `state` (RFC 9207), matching the `issuer` in AS metadata, so RFC 9207-compliant clients can validate it against `iss` after the redirect.

#### Client ID Metadata Documents (CIMD)

MCP spec `2026-07-28` deprecates Dynamic Client Registration (RFC 7591) in favor of CIMD, but idproxy supports both side by side — DCR-registered UUID client IDs keep working unchanged.

- A client presents an `https://` URL with a non-empty path (e.g. `https://client.example.com/.well-known/mcp-client.json`) as its `client_id`. `http://` URLs and path-less `https://` URLs (`https://example.com`, `https://example.com/`) never enter the CIMD path and are treated as regular (DCR/static) client IDs.
- idproxy fetches the URL, requiring a `200` response with an `application/json` body no larger than 5 KB; redirects are rejected. The document's `client_id` must match the fetch URL exactly, and `redirect_uris` must be non-empty — the authorization request's `redirect_uri` is checked against them the same way as a DCR-registered client.
- The fetch itself resolves the hostname and validates every resolved IP before dialing it (not the hostname after the fact), rejecting loopback, RFC 1918 private, link-local, unspecified, multicast, CGNAT (`100.64.0.0/10`), and IPv6 ULA (`fc00::/7`) ranges — this also closes off DNS rebinding, since the address that is checked is the exact address that is dialed.
- Successful fetches are cached in-process (never written to `Store`) for the response's `Cache-Control: max-age` when present, clamped to `[60s, 24h]`; the default is 15 minutes when no `max-age` is given, and `no-store`/`no-cache` responses are never cached. A fetch failure never falls back to a stale cache entry — it fails closed with `400 invalid_client`.
- `client_id_metadata_document_supported: true` is advertised in AS metadata (`/.well-known/oauth-authorization-server`).

### Connecting to a `focal` MCP server behind idproxy

[youyo/focal](https://github.com/youyo/focal)'s `focal serve` exposes an unauthenticated stateless Streamable HTTP MCP endpoint and expects an authenticating reverse proxy in front of it. idproxy's `UPSTREAM_URL` Unix domain socket support and `UPSTREAM_AUTH_TOKEN` map directly onto focal's two upstream-hardening options:

- **Same host, same UID — Unix domain socket.** Point `UPSTREAM_URL` at the socket focal listens on (`focal serve --listen unix:/run/focal/focal.sock`): `UPSTREAM_URL=unix:///run/focal/focal.sock`. The socket's `0600` permissions restrict reachability to the same user; idproxy and focal must run under the same UID.
- **Different hosts/containers — shared token.** Run `focal serve` with `FOCAL_UPSTREAM_TOKEN` set, and set idproxy's `UPSTREAM_AUTH_TOKEN` to the same value. idproxy injects `Authorization: Bearer <UPSTREAM_AUTH_TOKEN>` on every upstream request and strips whatever `Authorization` the client sent, so focal only ever sees the shared token, never the client's OAuth Bearer token.

Either way, the client-facing flow is unchanged: Claude Desktop (or another MCP client) authenticates against idproxy's OAuth 2.1 AS over `EXTERNAL_URL`, and idproxy forwards only authenticated requests to focal over `UPSTREAM_URL`.

## Refresh Token Rotation Design

idproxy implements OAuth 2.1 §4.3.2 refresh_token rotation with the following design:

- When a refresh_token is consumed, the old record is **marked as `used=true`** instead of being deleted.
- A new refresh_token is issued and linked to the same `family_id`.
- If an already-used refresh_token is presented again (replay), the entire family is revoked via a `familyrevoked:<family_id>` tombstone.

### Why keep the old record instead of deleting it?

OAuth 2.1 §4.3.2 requires the AS to "invalidate" the old refresh_token, not literally "delete" it. Keeping the record with `used=true`:

- Lets `ConsumeRefreshToken` reject reuse (satisfying the spec).
- Retains the `family_id` so replay detection can revoke the whole family.
- Expires automatically via TTL (30 days by default).

### Observability

Two structured log events cover the rotation lifecycle:

| Event | Level | When |
|-------|-------|------|
| `oauth refresh rotation` | Info | Successful rotation (new token issued) |
| `oauth refresh replay detected` | Warn | Reused token detected (family revoked) |

Both include `family_id`, `client_id`, and `scope` — never the refresh_token string itself.

### Observing rotation in production (DynamoDB)

When inspecting `refreshtoken:*` records, include the `used` attribute to distinguish live vs. already-rotated tokens:

```bash
aws dynamodb scan \
  --table-name my-idproxy-table \
  --filter-expression 'begins_with(pk, :prefix)' \
  --expression-attribute-values '{":prefix":{"S":"refreshtoken:"}}' \
  --projection-expression 'pk, #u, #t' \
  --expression-attribute-names '{"#u":"used","#t":"ttl"}'
```

`used=true` indicates the token has been rotated; it will be deleted by TTL.

## Store Backends

idproxy persists sessions, authorization codes, access/refresh tokens and dynamically registered clients via the `Store` interface. Several implementations are bundled:

| Backend | Package | Use case | TTL strategy | CAS for refresh rotation |
|---|---|---|---|---|
| Memory | `store` (`NewMemoryStore`) | Single-instance / dev / tests | In-process timer + Cleanup goroutine | Mutex |
| DynamoDB | `store` (`NewDynamoDBStore`) | AWS multi-container (Lambda) | DynamoDB TTL | `ConditionExpression` |
| SQLite | `store/sqlite` (`sqlite.New`) | Single-node file-based persistence (CGO-free) | Per-row `expires_at` + 5-min Cleanup goroutine | `BEGIN IMMEDIATE` + `used=0` CAS |
| Redis | `store/redis` (`redis.New`) | General-purpose distributed KV | Native `EX` | Embedded Lua script (`consume.lua`) |

When using the `idproxy` standalone binary, select a backend via the `STORE_BACKEND` environment variable. See the binary's `--help` or the [cmd/idproxy](cmd/idproxy) sources for required env vars per backend.

### Client / DB ownership (cheat sheet)

When you inject your own client / db into a Store via `*WithClient` /
`*WithDB`, ownership at `Close()` differs:

| Backend  | Default                            | How to opt out                                                |
| -------- | ---------------------------------- | ------------------------------------------------------------- |
| DynamoDB | **never** closes the injected client (AWS SDK v2 convention) | n/a                                                            |
| Redis    | closes (`client.Close()`)          | `redisstore.NewWithClient(client, prefix, redisstore.WithClientOwnership(false))` |
| SQLite   | closes (`db.Close()`)              | not yet exposed; `NewWithDB` is on the roadmap                 |

This means it is always safe to share a single `*dynamodb.Client` between
idproxy and your application code. For Redis, opt out of ownership if you
want to keep using the client after idproxy is shut down. Full discussion
in [`docs/store-coexistence.md`](docs/store-coexistence.md).

### Selecting from the binary

```sh
# SQLite
STORE_BACKEND=sqlite SQLITE_PATH=/var/lib/idproxy/state.db idproxy

# Redis
STORE_BACKEND=redis REDIS_ADDR=redis.internal:6379 idproxy

# DynamoDB
STORE_BACKEND=dynamodb DYNAMODB_TABLE_NAME=my-idproxy-table AWS_REGION=ap-northeast-1 idproxy
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

### Coexistence with user-owned tables / GSIs

idproxy is designed to share a DynamoDB table with your application data.
Reserved PK prefixes (lowercase): `session:`, `authcode:`, `accesstoken:`,
`client:`, `refreshtoken:`, `familyrevoked:`. idproxy never queries a GSI,
so you can add your own freely. See [`examples/dynamodb-coexist`](examples/dynamodb-coexist)
for a runnable example and [`docs/store-coexistence.md`](docs/store-coexistence.md)
for the full guide (TTL sharing, hot partitions, attribute-name conflicts).

> **Note**: `Cleanup()` is a no-op — expired items are removed automatically by DynamoDB TTL. DynamoDB TTL may have up to 48 hours of lag; `DynamoDBStore` compensates by checking the `ttl` attribute on every `Get` and returning `nil` for expired items.

## License

[MIT License](LICENSE)
