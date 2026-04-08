// Package idproxy provides OIDC authentication middleware and MCP OAuth 2.1
// Authorization Server functionality as a single Go library.
//
// idproxy can be used as:
//   - An http.Handler middleware via Auth.Wrap() for any Go HTTP server
//   - A standalone reverse proxy binary (cmd/idproxy) for non-Go upstream servers
//
// Features:
//   - Multiple OIDC provider support (EntraID, Google, etc.)
//   - MCP OAuth 2.1 Authorization Server with PKCE
//   - SSE/Streamable HTTP transparent passthrough
//   - Cookie-based session management with encrypted JWT
//   - Pluggable Store interface for session/token persistence
package idproxy
