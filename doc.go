// Package idproxy provides OIDC authentication middleware and MCP OAuth 2.1
// Authorization Server functionality as a single Go library.
//
// idproxy can be used as:
//   - An http.Handler middleware via Auth.Wrap() for any Go HTTP server
//   - A standalone reverse proxy binary (cmd/idproxy) for non-Go upstream servers
//
// # Features
//
//   - Multiple OIDC provider support (EntraID, Google, Amazon Cognito, etc.)
//   - MCP OAuth 2.1 Authorization Server with PKCE (S256 only)
//   - SSE / Streamable HTTP transparent passthrough
//   - Cookie-based session management with encrypted JWT (gorilla/securecookie)
//   - Pluggable Store interface for session/token persistence
//     (memory / DynamoDB / Redis / SQLite implementations)
//   - Dynamic Client Registration (RFC 7591)
//   - OAuth 2.1 refresh_token rotation with family revocation
//
// # Authentication flow (browser session)
//
//  1. Client request hits Auth.Wrap().
//  2. If the request matches a BrowserAuth path (/login, /callback, /select),
//     the corresponding handler is invoked.
//  3. If the request has an Authorization: Bearer <jwt> header, the JWT is
//     validated against the configured signing key and the user is injected
//     into the request context.
//  4. If the request has a session cookie, the cookie is decrypted and the
//     session is fetched from Store; on success the user is injected.
//  5. Otherwise: browser requests (Accept: text/html) are redirected to
//     /login, API requests get 401 Unauthorized.
//
// # Post-login redirect behavior (v0.5.0+)
//
// After authentication completes, BrowserAuth redirects the user back to:
//
//   - The redirect_to query parameter passed to /login, if supplied.
//   - Otherwise Config.DefaultPostLoginPath, if non-empty.
//   - Otherwise "/" (legacy default).
//
// Embedding applications that previously relied on the default "/" should
// either keep a handler mounted at "/", or set DefaultPostLoginPath. To run
// arbitrary post-authentication logic (e.g. cascade OAuth, account
// provisioning, audit logging), use the Config.OnAuthenticated hook. The
// hook is called once, right after the session cookie is issued.
//
// See the README and examples/cascade-oauth for details.
//
// # Open redirect protection (opt-in, v0.5.0+)
//
// idproxy accepts arbitrary redirect_to values by default (legacy behavior).
// To prevent open-redirect attacks, opt in with
// (*Config).UseStrictPostLoginRedirectValidator() or by setting
// Config.PostLoginRedirectValidator manually.
//
// The strict validator allows only:
//   - Relative paths starting with "/" (but not "//")
//   - Absolute HTTPS URLs whose host equals Config.ExternalURL's host
//
// All other inputs (javascript:, data:, protocol-relative, backslashes,
// non-NFKC characters, control / format characters) are rejected with 400.
//
// # Store backend selection
//
// Pick the Store implementation based on deployment topology:
//
//   - store.NewMemoryStore()       — single instance, no persistence
//   - store.NewDynamoDBStore(...)  — Lambda / multi-instance / multi-AZ
//   - redis (store/redis package)  — distributed cache, low-latency sessions
//   - sqlite (store/sqlite package)— single node with disk persistence
//
// All implementations share the same Store interface. Refresh-token rotation
// is implemented with backend-specific atomicity primitives (Lua script for
// Redis, transaction CAS for SQLite, conditional update for DynamoDB).
//
// # Client ownership in Store implementations
//
// When you pass an externally-constructed client / db to a Store, ownership
// of that resource determines what happens at Close():
//
//   - DynamoDB: never closes the injected client (AWS SDK v2 convention).
//   - Redis:    closes the injected client by default;
//               opt out with redisstore.WithClientOwnership(false).
//   - SQLite:   closes the injected db by default
//               (NewWithDB is not yet exposed in v0.5.0; see roadmap).
//
// See docs/store-coexistence.md for the full coexistence guide.
package idproxy
