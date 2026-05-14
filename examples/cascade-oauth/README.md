# Example: Cascade OAuth (idproxy `OnAuthenticated` hook)

This example demonstrates the **cascade OAuth pattern**: after the user
authenticates with idproxy (OIDC), the application checks whether the user
is also connected to an external OAuth provider (Slack / Backlog / kintone /
GitHub / Notion / etc.) and, if not, redirects them to start the external
OAuth flow.

This pattern is common when idproxy is used as a session gateway for an
application that itself calls third-party APIs on behalf of the user.

## How it works

1. User opens `/protected`.
2. `idproxy.Auth.Wrap` sees no session → redirects to `/login`.
3. `/login` → external OIDC IdP (Entra ID, Google, etc.) → `/callback`.
4. **`Config.OnAuthenticated` is called** with the new `*idproxy.User`.
   - If the user already has an external OAuth token: hook returns
     `("", false)` and BrowserAuth follows the normal redirect.
   - If the user is **not** yet connected: hook returns
     `("/oauth/external/start?return_to=...", false)` and BrowserAuth
     redirects there instead.
5. `/oauth/external/start` (stubbed in this example) issues a token and
   redirects back to the original URL.

## Run locally

```bash
export EXTERNAL_URL="http://localhost:8080"
export COOKIE_SECRET="$(openssl rand -hex 32)"
export OIDC_ISSUER="https://login.microsoftonline.com/{tenant}/v2.0"
export OIDC_CLIENT_ID="xxxx"
export OIDC_CLIENT_SECRET="xxxx"

go run .
```

Open `http://localhost:8080/protected` — you should be bounced to
`/login` → IdP → `/callback` → `/oauth/external/start` → `/protected`
on the first visit, then directly to `/protected` on subsequent visits.

## Migration: from middleware pattern to `OnAuthenticated`

Many applications historically implemented this by wrapping their own
middleware around `idproxy.Auth.Wrap`. With v0.5.0 the `OnAuthenticated`
hook lets you do the same in **one place, at the right time** (right after
session issuance), without an extra middleware layer.

### Before — middleware pattern

```go
// MyMiddleware enforces external OAuth connection on every request.
func MyMiddleware(tokenStore *externalTokenStore, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user := idproxy.UserFromContext(r.Context())
        if user != nil && !tokenStore.HasToken(user.Email) {
            // 全リクエストごとに評価される（無駄）
            http.Redirect(w, r, "/oauth/external/start", http.StatusFound)
            return
        }
        next.ServeHTTP(w, r)
    })
}

mux := http.NewServeMux()
mux.HandleFunc("/protected", protectedHandler)
http.ListenAndServe(":8080", auth.Wrap(MyMiddleware(tokenStore, mux)))
```

Problems:

- Runs on every authenticated request, not just on first login.
- Has to be added around every handler; missing it on one entry is a bug.
- The decision logic is split from idproxy's auth flow.

### After — `OnAuthenticated` hook

```go
cfg := idproxy.Config{
    // ...
    OnAuthenticated: func(w http.ResponseWriter, r *http.Request, user *idproxy.User) (string, bool) {
        if !tokenStore.HasToken(user.Email) {
            return "/oauth/external/start?return_to=" + r.URL.Query().Get("redirect_to"), false
        }
        return "", false
    },
}
cfg.UseStrictPostLoginRedirectValidator() // recommend opt-in
```

Benefits:

- Runs **once**, right after the session is issued.
- Lives next to your `Config`, no extra middleware to remember.
- Plays nicely with `PostLoginRedirectValidator` (the returned `redirectTo`
  is automatically passed through your validator).

### Real-world adoption

- [logvalet](https://github.com/youyo/logvalet) — Backlog MCP server that
  uses this pattern to bridge OIDC sessions with backlog.com OAuth tokens.

## Caveats

This example focuses on the **flow-control piece** (when to redirect).
A production cascade-OAuth implementation also has to deal with:

- Where to persist the external token (in idproxy's `Store` or a separate
  backend?). See [`docs/store-coexistence.md`](../../docs/store-coexistence.md).
- Refresh-token rotation for the external provider.
- Race conditions when idproxy session and external token expire at
  different times.
- Concurrent OAuth flows from multiple tabs (state collision).

Those are documented in [`docs/cascade-oauth-pattern.md`](../../docs/cascade-oauth-pattern.md).
