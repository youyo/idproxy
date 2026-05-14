# Store coexistence guide

idproxy ships with four `Store` implementations:

- `store.NewMemoryStore()` — in-process map, default
- `store.NewDynamoDBStore(...)` / `store.NewDynamoDBStoreWithClient(...)`
- `store/redis` — go-redis v9 client
- `store/sqlite` — `modernc.org/sqlite` (pure-Go, no CGO)

This document explains how to **mix idproxy's Store with your own
application data on the same backend** without conflicts, and how each
implementation handles the lifecycle of an externally-injected
client / db.

## Client ownership matrix

When you call a `*WithClient` / `*WithDB` constructor, you can ask whether
the Store should close the underlying client at `Close()` or leave it
alone (so your application code can keep using it).

| Backend  | Default for injected client       | How to opt out                                                   |
| -------- | --------------------------------- | ---------------------------------------------------------------- |
| DynamoDB | **never closes**                  | N/A — `Close()` is intentionally a no-op for the client (it only marks the Store as closed) |
| Redis    | closes (`client.Close()`)         | `redisstore.NewWithClient(client, prefix, redisstore.WithClientOwnership(false))` |
| SQLite   | closes (`db.Close()`)             | currently no public API — `NewWithDB(*sql.DB)` is on the roadmap (see "Future work" below) |
| Memory   | not applicable                    | not applicable                                                   |

### Why is DynamoDB different?

The AWS SDK v2 client does not implement `io.Closer`. It owns no
connection pool that needs to be flushed; the underlying HTTP/2 transport
is shared with the rest of the SDK and is garbage-collected automatically.
Closing it would be a no-op at best and an antipattern at worst.

So idproxy never closes the injected DynamoDB client. This means **it is
always safe to share the same `*dynamodb.Client` between idproxy and your
application code** without any opt-in flag.

### Why does Redis default to "close"?

go-redis's `Client.Close()` shuts down its internal connection pool. If
idproxy is the sole user of that client, you want the pool drained on
`Store.Close()`. If your application also uses the same client for
business queries, you want the pool to outlive idproxy — set
`WithClientOwnership(false)`.

## Sharing a single DynamoDB table

idproxy uses these reserved primary-key prefixes (all lowercase):

- `session:<id>`
- `authcode:<code>`
- `accesstoken:<jti>`
- `client:<client_id>`
- `refreshtoken:<id>`
- `familyrevoked:<family_id>`

The data attribute is named `data` (String, JSON-encoded). TTL is `ttl`
(Number, Unix epoch seconds). Refresh-token state is `used` (Number, 0/1).

To coexist, your application data should:

1. **Pick a primary-key prefix that doesn't collide** with the six above.
   We recommend `_app:` (underscore so any future idproxy prefix sorted
   without it stays clearly disjoint).
2. **Use a different value-attribute name** (`app_data`, `payload`, etc.).
   Reusing `data` works too, but only if your schema also tolerates the
   JSON shape idproxy writes.
3. **TTL is safe to share.** DynamoDB's TTL service deletes any item
   whose `ttl` attribute is in the past, regardless of who wrote it.
4. **GSIs are free to add.** idproxy never queries a GSI. Adding GSIs
   (or LSIs) on attributes idproxy never writes has no impact on idproxy.
5. **Don't touch the `used` attribute on idproxy rows.** Setting it on
   a `refreshtoken:` item would silently bypass replay detection.

### Read consistency

idproxy enables `ConsistentRead` on `GetSession` and `GetAuthCode` to
defend against multi-instance race conditions (e.g. Lambda cold starts
hitting the table the same millisecond as the previous warm container).
For your own queries, choose the read mode based on your access pattern;
idproxy's choice has no spillover effect.

### TTL lag

DynamoDB's native TTL deletion can lag by **up to 48 hours**. idproxy
compensates by reading the `ttl` attribute on every `Get*` and returning
`(nil, nil)` when expired. Your application can do the same trick for
items whose TTL semantics need to be strict.

### Minimum IAM policy

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
      "Resource": "arn:aws:dynamodb:REGION:ACCOUNT:table/TABLE"
    }
  ]
}
```

GSI permissions are required only if your application queries them
(`dynamodb:Query` on `index/*`). idproxy itself never touches a GSI.

## Sharing a Redis instance

Redis is partitioned by key, not by database. To coexist:

1. Always use a **non-empty `KeyPrefix`** (e.g. `idproxy:` or
   `myapp:idp:`). idproxy writes only inside that prefix.
2. Your application picks a different prefix (`myapp:`) and queries it
   independently.
3. There is no GSI concept — no further isolation work is needed.

```go
import (
    "github.com/redis/go-redis/v9"
    redisstore "github.com/youyo/idproxy/store/redis"
)

client := redis.NewUniversalClient(&redis.UniversalOptions{
    Addrs: []string{"localhost:6379"},
})
defer client.Close()

s := redisstore.NewWithClient(client, "idproxy:", redisstore.WithClientOwnership(false))
defer s.Close() // does NOT close the client thanks to WithClientOwnership(false)
```

Your application can keep using `client` after idproxy is shut down.

## Sharing a SQLite database file

idproxy currently uses **its own table set** (`sessions`, `authcodes`,
`accesstokens`, `clients`, `refreshtokens`, `family_revocations`) inside
the SQLite database it opens.

> ⚠️ **As of v0.5.0 you cannot pass an externally-opened `*sql.DB` into
> the SQLite Store.** The current public API only exposes
> `sqlitestore.New(path)` and `sqlitestore.NewWithCleanupInterval(...)`,
> which open the database with a specific DSN
> (`_txlock=immediate`, `busy_timeout=5000`, `journal_mode=WAL`,
> `foreign_keys=on`). Those PRAGMA settings are load-bearing for the
> refresh-token CAS guarantees and are not safe to relax silently.

A future release will expose `NewWithDB(*sql.DB, ...Option)` once the
PRAGMA contract is documented and enforceable at runtime; until then, run
idproxy and your application against a shared file path rather than a
shared `*sql.DB`.

### Future work

- `sqlitestore.NewWithDB(*sql.DB)` with documented PRAGMA contract.
- `sqlitestore.WithDBOwnership(bool)` Option mirroring Redis.
- `sqlitestore.WithCustomSchema(prefix)` for explicit table-name disambiguation.

Track this in the
[idproxy roadmap](../plans/idproxy-roadmap.md) under M24+ candidates.

## Lifecycle ordering at shutdown

When idproxy and your application share a backend, shut them down in the
right order:

```
ctx, cancel := context.WithCancel(...)
defer cancel()

// 1. Stop accepting new requests (e.g. http.Server.Shutdown)
// 2. Close idproxy Store (flushes any in-flight Cleanup)
_ = idproxyStore.Close()
// 3. Close application code that uses the shared client
_ = appCode.Close()
// 4. Close the shared client itself
_ = sharedClient.Close()
```

If you opt for `WithClientOwnership(true)` (default for Redis), step 2
already closes the shared client; step 4 must be skipped to avoid the
double-close error path. The reverse is also true: with
`WithClientOwnership(false)`, you must remember step 4.

## Failure modes worth knowing

- **Cookie secret rotation.** idproxy treats `Config.CookieSecret` as
  the HMAC key for session-cookie integrity. If you rotate it while
  sessions exist in the Store, those sessions become unreadable (clients
  see "invalid cookie" and are redirected to `/login`).
- **TTL precision.** Memory and SQLite use millisecond-precise expiry;
  DynamoDB and Redis honor TTL at the second. A session that expires in
  the middle of a request usually still completes.
- **Hot partitions on DynamoDB.** Heavy login traffic creates many
  short-lived items under the `session:` prefix. DynamoDB's adaptive
  capacity handles this well in `PAY_PER_REQUEST` mode; with provisioned
  capacity, consider isolating idproxy into its own table to avoid
  competing with application writes.
