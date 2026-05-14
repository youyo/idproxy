# Cascade OAuth pattern

idproxy handles the **session identity** (who is this user, are they
authenticated). Many real applications also need a **second OAuth flow**
to talk to a third-party API on the user's behalf:

- A Slack-integrated dashboard needs the user's Slack token.
- A Backlog MCP server needs the user's backlog.com OAuth grant.
- A kintone integration needs the user's kintone API session.

This second flow is independent of idproxy's OIDC login. It produces a
token whose lifetime and revocation semantics are owned by the external
provider. We call the combination of "idproxy OIDC session" plus
"external OAuth token" a **cascade**.

This guide explains the moving parts. The minimal flow-control snippet is
in [`examples/cascade-oauth`](../examples/cascade-oauth/).

## 1. Responsibility split

| Concern                                | Owner                         | Backing data                            |
| -------------------------------------- | ----------------------------- | --------------------------------------- |
| Who is the user                        | idproxy session               | idproxy Store (`session:<id>`)         |
| Is the user allowed on this app        | idproxy `AllowedDomains` / `AllowedEmails` | idproxy Config                          |
| Does the user have an external token   | Application                   | Application Store (your choice)         |
| External token TTL / refresh           | Application                   | Application Store                       |
| Revocation / disconnect                | Application                   | Application Store                       |
| Auditing of identity events            | idproxy + Application logs    | slog                                    |

The crucial split is "**idproxy doesn't know anything about the external
token, and shouldn't**". The application owns it end-to-end. idproxy's only
contribution is the `OnAuthenticated` hook that lets you intercept the
post-login flow exactly once, right after the session cookie is issued.

### Lifecycle diagram

```
        ┌──────────┐                ┌──────────────┐                ┌──────────────┐
Browser │  /protected request       │              │                │              │
   ───▶ │ idproxy  │  OIDC login    │  OIDC IdP    │                │ external API │
        │  (you)   │ ◀───────────▶ │ (Entra ID,    │                │ (Slack /     │
        └─────┬────┘                │  Google ...) │                │  Backlog ...)│
              │ OnAuthenticated     └──────────────┘                └───────┬──────┘
              │  decides next       (idproxy's responsibility ends here)    │
              ▼                                                              │
        ┌──────────────────┐       ┌──────────────────┐                      │
        │ has external     │ no   │ /oauth/external/  │  external OAuth     │
        │ token?           ├────▶ │ start             │  authorize           │
        │                  │      │                   │ ──────────────────▶ │
        │                  │ yes  │                   │                      │
        ├─ proceed to ─────┘      │                   │ ◀── code, state ── │
        │  redirect_to            │                   │                      │
        ▼                          │                   │  exchange code      │
        protected resource         └────────┬──────────┘ ──────────────────▶ │
                                            │                                │
                                            ▼  external token in app Store   │
                                       redirect back to redirect_to          │
```

## 2. Where to store the external token

Three reasonable choices:

### (a) Same Store as idproxy (shared backend, separate namespace)

- **Pros**: Single backend to manage; the same TTL infrastructure
  (DynamoDB native TTL, Redis EXPIRE, SQLite cleanup ticker).
- **Cons**: idproxy's Store interface only exposes its own concepts
  (`Session`, `AuthCode`, etc.). You'll need to use the raw client
  alongside the Store.
- **Recommendation**: use `_app:` PK prefix on DynamoDB,
  `myapp:` key prefix on Redis. See
  [`docs/store-coexistence.md`](store-coexistence.md).

### (b) Separate Store (e.g. application Postgres)

- **Pros**: Decoupled migrations; idproxy can stay on DynamoDB while
  application data lives in Postgres.
- **Cons**: Two backups, two HA stories, two latency budgets.
- **Recommendation**: choose this when the application is already a
  database-driven monolith.

### (c) In-memory (only for stateless demos)

- **Pros**: Trivial to set up.
- **Cons**: Token lost on restart; doesn't scale beyond one instance.
- **Recommendation**: examples only.

## 3. State management for the external authorize flow

The external OAuth provider asks for a `state` parameter to defend against
CSRF. You **cannot reuse idproxy's session ID** as the OAuth state — the
session ID is opaque to your application and would leak to the external
provider in the URL.

A robust pattern:

```go
// 1. Generate a fresh, single-use state.
extState := randHex(32)

// 2. Store it server-side with TTL ~ 10 minutes, tied to the current user.
appStore.SetOAuthState(ctx, extState, OAuthStateData{
    UserEmail: user.Email,
    ReturnTo:  returnTo,
    CreatedAt: time.Now(),
}, 10 * time.Minute)

// 3. Redirect to the external provider.
http.Redirect(w, r, fmt.Sprintf(
    "https://external.example.com/oauth/authorize?response_type=code&client_id=...&state=%s&redirect_uri=...",
    extState,
), http.StatusFound)
```

On the callback:

```go
data, err := appStore.GetOAuthState(ctx, r.URL.Query().Get("state"))
if err != nil || data == nil {
    http.Error(w, "invalid state", http.StatusBadRequest); return
}
// delete state to prevent reuse
_ = appStore.DeleteOAuthState(ctx, r.URL.Query().Get("state"))

// exchange code → token, persist external token tied to data.UserEmail
```

## 4. Failure & re-connection flows

The two tokens can fail independently. Plan for the cross-product:

| idproxy session | External token | What to do                                       |
| --------------- | -------------- | ------------------------------------------------ |
| valid           | valid          | Proceed. Application uses the external token.    |
| valid           | expired        | Refresh if possible; otherwise restart external flow. |
| valid           | revoked        | Redirect to `/oauth/external/start`.             |
| expired         | valid          | Redirect to `/login` (idproxy handles).          |
| expired         | expired        | Redirect to `/login`; external flow follows.     |

### Refresh-token rotation for the external provider

idproxy does refresh-token rotation **for its own MCP OAuth issuance**
(see refresh_token rotation in README). That has no bearing on your
external provider, which has its own refresh-token semantics. Implement
the external refresh in the application code:

```go
if extToken.ExpiresAt.Before(time.Now().Add(60 * time.Second)) {
    extToken, err = externalClient.Refresh(ctx, extToken.RefreshToken)
    if err != nil {
        // Could not refresh; force re-connect via /oauth/external/start.
        http.Redirect(w, r, "/oauth/external/start?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
        return
    }
    _ = appStore.SaveExternalToken(ctx, user.Email, extToken)
}
```

### Retry strategy

- Network blips on token-exchange: retry with exponential backoff for
  idempotent endpoints (most `/token` endpoints are not idempotent
  because they consume the `code`; treat the first failure as fatal).
- Provider 5xx: surface to the user with a "try again" message rather
  than auto-retrying — the user might have to re-consent.
- Race between two browser tabs: include the `state` parameter when
  reaching `/oauth/external/start` and reject any callback whose state
  doesn't match a row in `appStore`.

## 5. Security checklist

- [ ] Encrypt external tokens at rest (your application's Store, not idproxy's).
- [ ] Use `PostLoginRedirectValidator` (Strict) so an attacker cannot pass
      `redirect_to=https://attacker.example.com` and end up bouncing
      through `/oauth/external/start` to harvest tokens.
- [ ] Never log the external token. Log the `user.Email` + `state` for
      audit, but redact the token.
- [ ] Pin allowed external providers via the application config; never
      let `redirect_to` choose which provider to call.
- [ ] If the external provider grants long-lived tokens, define a
      rotation cadence and a kill-switch.

## 6. Real-world adoptions

- **logvalet** ([github.com/youyo/logvalet](https://github.com/youyo/logvalet))
  — Backlog MCP server. Uses idproxy's `OnAuthenticated` hook to detect
  missing backlog.com OAuth state and redirect to its connect flow.

If you've adopted this pattern publicly, send a PR adding your project
here.

## 7. Anti-patterns

- **Storing the external token in the idproxy session cookie.** The
  cookie is signed (HMAC), not encrypted at rest; it travels on every
  request; rotating it forces every user to re-login.
- **Reusing the idproxy session ID as the external `state`.** Leaks
  session identifier to a third party.
- **Calling the external provider from middleware.** Couples every
  request to provider latency; do the connect once at login and then
  use the cached token.
