[English](README.md) | **日本語**

# idproxy

OIDC 認証リバースプロキシ + MCP OAuth 2.1 Authorization Server。

idproxy は任意の HTTP バックエンドの前段に配置し、OIDC によるブラウザ認証と OAuth 2.1 Bearer Token 検証を透過的に提供します。MCP (Model Context Protocol) サーバーを保護する OAuth 2.1 AS としても動作し、Dynamic Client Registration (RFC 7591) をサポートします。

## 特徴

- OIDC ベースのブラウザ認証（Google, Microsoft Entra ID 等）
- OAuth 2.1 Authorization Server（PKCE 必須、Bearer Token 発行、refresh_token ローテーション）
- Dynamic Client Registration (RFC 7591)
- SSE (Server-Sent Events) 透過プロキシ
- MCP サーバー保護に最適化
- ゼロ依存のインメモリセッションストア（本番用に差し替え可能）

## インストール

### Go

```bash
go install github.com/youyo/idproxy/cmd/idproxy@latest
```

### Docker

```bash
docker pull ghcr.io/youyo/idproxy:latest
```

## クイックスタート

### 環境変数を設定して起動

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

## 環境変数

### 必須

| 変数名 | 説明 | 例 |
|--------|------|-----|
| `UPSTREAM_URL` | プロキシ先のバックエンド URL | `http://localhost:3000` |
| `EXTERNAL_URL` | このサービスの外部公開 URL | `https://mcp-auth.example.com` |
| `COOKIE_SECRET` | Cookie 暗号化キー（hex エンコード、32 バイト以上） | `openssl rand -hex 32` で生成 |
| `OIDC_ISSUER` | OIDC Issuer URL（カンマ区切りで複数指定可） | `https://accounts.google.com` |
| `OIDC_CLIENT_ID` | OAuth Client ID（カンマ区切りで複数指定可） | `your-client-id` |

### オプション

| 変数名 | 説明 | デフォルト |
|--------|------|----------|
| `OIDC_CLIENT_SECRET` | OAuth Client Secret（カンマ区切りで複数指定可） | なし |
| `OIDC_PROVIDER_NAME` | プロバイダー表示名（カンマ区切りで複数指定可） | Issuer から自動生成 |
| `ALLOWED_DOMAINS` | 許可メールドメイン（カンマ区切り） | 制限なし |
| `ALLOWED_EMAILS` | 許可メールアドレス（カンマ区切り） | 制限なし |
| `PATH_PREFIX` | OAuth 2.1 AS エンドポイントのパスプレフィックス | なし |
| `PORT` | リッスンポート | `8080` |

## プロバイダー設定

| プロバイダー | `OIDC_ISSUER` | 設定ガイド |
|-------------|--------------|-----------|
| Google | `https://accounts.google.com` | [OpenID Connect — Google Identity](https://developers.google.com/identity/openid-connect/openid-connect) |
| Microsoft Entra ID | `https://login.microsoftonline.com/{tenant-id}/v2.0` | [アプリケーションの登録 — Microsoft ID プラットフォーム](https://learn.microsoft.com/ja-jp/entra/identity-platform/quickstart-register-app) |

OIDC プロバイダーへ idproxy をクライアントとして登録する際は、リダイレクト URI を以下のように設定してください：

```
{EXTERNAL_URL}/auth/callback
```

## ライブラリとしての使い方

idproxy は Go ライブラリとしても利用できます。

### 基本的なリバースプロキシ

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

### MCP サーバー保護（OAuth 2.1 AS）

`Config.OAuth` を設定すると、`Auth.New()` が OAuthServer を自動で構築します。

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
		RefreshTokenTTL: 30 * 24 * time.Hour, // 30 日
		OAuth: &idproxy.OAuthConfig{
			SigningKey: signingKey,
		},
	}

	// OAuth 設定があれば OAuthServer も自動初期化される
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

## リフレッシュトークン Rotation の設計方針

idproxy は OAuth 2.1 §4.3.2 に準拠した refresh_token rotation を以下の設計で実装しています:

- refresh_token が消費されると、旧レコードは削除せず **`used=true` フラグを立てる**
- 新 refresh_token を発行し、同一 `family_id` に紐付ける
- 使用済み refresh_token が再度提示された場合（replay）は `familyrevoked:<family_id>` tombstone で family 全体を無効化

### なぜ削除せず `used=true` マークなのか

OAuth 2.1 §4.3.2 は旧 refresh_token の "invalidate" を要求していますが、これは "delete" ではありません。`used=true` マーク方式には以下の利点があります:

- `ConsumeRefreshToken` が再利用を拒否（仕様を満たす）
- `family_id` を保持することで replay 検知時に family 全体を revoke 可能
- TTL（デフォルト 30 日）により自動削除

### 可観測性

rotation ライフサイクルは 2 つの構造化ログイベントでカバーされます:

| イベント | レベル | タイミング |
|---------|--------|-----------|
| `oauth refresh rotation` | Info | rotation 成功時（新 token 発行） |
| `oauth refresh replay detected` | Warn | 再利用検知時（family revoke） |

両者とも `family_id` / `client_id` / `scope` を含み、refresh_token 文字列そのものは**決して含めません**。

### 本番 DynamoDB での rotation 観察

`refreshtoken:*` レコードを scan する際は `used` 属性を projection に含めることで、live なトークンと rotation 済みトークンを区別できます:

```bash
aws dynamodb scan \
  --table-name my-idproxy-table \
  --filter-expression 'begins_with(pk, :prefix)' \
  --expression-attribute-values '{":prefix":{"S":"refreshtoken:"}}' \
  --projection-expression 'pk, #u, #t' \
  --expression-attribute-names '{"#u":"used","#t":"ttl"}'
```

`used=true` は rotation 済みを示し、TTL により自動削除されます。

## Store バックエンド

idproxy はセッション・認可コード・アクセス/リフレッシュトークン・動的登録クライアントを `Store` インターフェース経由で永続化します。以下の実装を同梱しています。

| バックエンド | パッケージ | 用途 | TTL 戦略 | refresh rotation の CAS |
|---|---|---|---|---|
| Memory | `store` (`NewMemoryStore`) | 単一インスタンス／開発／テスト | In-process タイマー + Cleanup ゴルーチン | Mutex |
| DynamoDB | `store` (`NewDynamoDBStore`) | AWS マルチコンテナ (Lambda) | DynamoDB TTL | `ConditionExpression` |
| SQLite | `store/sqlite` (`sqlite.New`) | 単一ノードのファイル永続化（CGO 不要） | 行ごとの `expires_at` + 5 分 Cleanup ゴルーチン | `BEGIN IMMEDIATE` + `used=0` CAS |
| Redis | `store/redis` (`redis.New`) | 汎用分散 KV | ネイティブ `EX` | 埋め込み Lua script (`consume.lua`) |
| Momento | `store/momento` (`momento.New`) | サーバーレス分散キャッシュ | ネイティブ TTL | `SetIfEqual` |

`idproxy` バイナリ利用時は `STORE_BACKEND` 環境変数でバックエンドを選択できます。各バックエンドが要求する env はバイナリの `--help` または [cmd/idproxy](cmd/idproxy) のソースを参照してください。

### バイナリでの切替

```sh
# SQLite
STORE_BACKEND=sqlite SQLITE_PATH=/var/lib/idproxy/state.db idproxy

# Redis
STORE_BACKEND=redis REDIS_ADDR=redis.internal:6379 idproxy

# Momento
STORE_BACKEND=momento MOMENTO_AUTH_TOKEN=... MOMENTO_CACHE_NAME=idproxy idproxy

# DynamoDB
STORE_BACKEND=dynamodb DYNAMODB_TABLE_NAME=my-idproxy-table AWS_REGION=ap-northeast-1 idproxy
```

## DynamoDB Store

AWS Lambda のマルチコンテナ環境など、複数インスタンスで状態を共有する必要がある場合は `DynamoDBStore` を使用します。

### 使い方

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

### DynamoDB テーブル作成

```bash
aws dynamodb create-table \
  --table-name my-idproxy-table \
  --attribute-definitions AttributeName=pk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region ap-northeast-1

# ttl 属性で TTL を有効化
aws dynamodb update-time-to-live \
  --table-name my-idproxy-table \
  --time-to-live-specification "Enabled=true,AttributeName=ttl" \
  --region ap-northeast-1
```

### IAM 権限（最小構成）

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

> **セキュリティ**: `data` 属性にはセッションデータやアクセストークン等の機密情報が含まれます。本番環境では [AWS KMS による DynamoDB サーバーサイド暗号化 (SSE-KMS)](https://docs.aws.amazon.com/ja_jp/amazondynamodb/latest/developerguide/EncryptionAtRest.html) を有効にすることを強く推奨します。

> **注意**: `Cleanup()` は no-op です。期限切れアイテムは DynamoDB TTL が自動削除します。DynamoDB TTL には最大 48 時間の遅延がありますが、`DynamoDBStore` はすべての `Get` 時に `ttl` 属性と現在時刻を比較し、期限切れの場合は `nil` を返す実装でこれを補完しています。

## ライセンス

[MIT License](LICENSE)
