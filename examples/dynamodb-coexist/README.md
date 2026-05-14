# Example: DynamoDB coexistence (idproxy Store + application data in one table)

This example shows how to host idproxy's DynamoDB Store and your own
application data in **the same DynamoDB table**, without conflicts.

## Why one table?

- A single table is cheaper (single PAY_PER_REQUEST throughput pool).
- One IAM policy, one CloudFormation resource.
- The application and idproxy share the same DynamoDB client and AWS
  connection pool.

idproxy's DynamoDB Store is designed to coexist:

| Attribute / behavior     | idproxy contract                                              | Recommendation for coexisting apps                       |
| ------------------------ | ------------------------------------------------------------- | -------------------------------------------------------- |
| Primary key attribute    | `pk` (lowercase)                                              | Use the same `pk` attribute for both namespaces           |
| Item value attribute     | `data` (String, JSON)                                         | Pick a different name (e.g. `app_data`) for your items   |
| TTL attribute            | `ttl` (Unix epoch seconds, Number)                            | You can reuse `ttl` for both                              |
| Refresh-token `used` bit | `used` (Number, 0/1)                                          | Don't write your own `used` attribute on idproxy rows    |
| PK prefixes (reserved)   | `session:`, `authcode:`, `accesstoken:`, `client:`, `refreshtoken:`, `familyrevoked:` | Choose any prefix that does not match these (e.g. `_app:`) |
| GSI usage                | idproxy does **not** use any GSI                              | Free to add your own GSIs                                 |
| Client lifecycle         | `Close()` does **not** call `client.Close()`                  | Safe to share the `*dynamodb.Client` with your app code  |

## Run

```bash
export AWS_REGION="us-east-1"
export DYNAMODB_TABLE="idproxy-coexist-example"
export EXTERNAL_URL="https://app.example.com"
export COOKIE_SECRET="$(openssl rand -hex 32)"
export OIDC_ISSUER="https://login.microsoftonline.com/{tenant}/v2.0"
export OIDC_CLIENT_ID="xxxx"
export OIDC_CLIENT_SECRET="xxxx"

aws dynamodb create-table --cli-input-json file://table.json
go run .
```

## Minimum IAM policy

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
      "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/idproxy-coexist-example"
    },
    {
      "Effect": "Allow",
      "Action": ["dynamodb:Query"],
      "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/idproxy-coexist-example/index/*"
    }
  ]
}
```

idproxy itself only needs `GetItem` / `PutItem` / `DeleteItem` on the base
table. The `Query` permission on `index/*` is for your own GSI-based queries.

## TTL handling

DynamoDB's native TTL has a deletion lag of up to 48 hours. idproxy already
compensates by reading the `ttl` attribute on every Get and returning
`(nil, nil)` when expired, so coexisting items don't need to worry about
stale idproxy rows showing up in their scans.

For your own data, you can either:

1. Reuse the `ttl` attribute (DynamoDB's TTL service will delete those too).
2. Use a different attribute name and disable TTL for those items.

## Hot partition warning

idproxy uses `pk` as the only partition key. If you also store application
data with `pk` values that share a common prefix (e.g. all `_app:user:*` for
a single tenant), DynamoDB's adaptive scaling will still keep latency low,
but heavy write contention on a single PK can throttle. Split your hot
partitions with a hash suffix (`_app:user:<email>:<shard>`) if you observe
`ProvisionedThroughputExceededException`.

## See also

- [`docs/store-coexistence.md`](../../docs/store-coexistence.md) — full
  Store coexistence guide (Redis, SQLite, DynamoDB).
