# M08 実装詳細計画: テストユーティリティ（モック IdP）

## Meta
| 項目 | 値 |
|------|---|
| マイルストーン | M08 |
| 対象ファイル | testutil/mock_idp.go, testutil/mock_idp_test.go |
| 作成日 | 2026-04-09 |
| ステータス | Draft |

---

## 目標

go-oidc ライブラリと互換性のある、テスト専用 OIDC IdP サーバーを `testutil` パッケージに実装する。
M10（ProviderManager）・M11（ブラウザ認証フロー）・M19（統合テスト）での利用を想定。

---

## 実装するエンドポイント

| エンドポイント | メソッド | 説明 |
|--------------|---------|------|
| `/.well-known/openid-configuration` | GET | OIDC Discovery Document |
| `/jwks` | GET | JSON Web Key Set |
| `/authorize` | GET | Authorization Code 発行 → コールバックリダイレクト |
| `/token` | POST | Authorization Code → ID Token 発行 |

---

## 設計方針

### 1. MockIdP 構造体

```go
type MockIdP struct {
    Server     *httptest.Server
    privateKey *ecdsa.PrivateKey
    keyID      string
    // 発行済みコード管理
    codes      map[string]codeEntry
    mu         sync.Mutex
}

type codeEntry struct {
    subject  string
    email    string
    nonce    string
    clientID string
}
```

### 2. コンストラクタ

```go
// NewMockIdP は httptest.Server を起動し、MockIdP を返す。
// テスト終了時は t.Cleanup で Close() が呼ばれる。
func NewMockIdP(t testing.TB) *MockIdP
```

- `t.Cleanup(m.Close)` で自動クリーンアップ
- ES256 鍵ペアを動的生成（ecdsa.GenerateKey(elliptic.P256, rand.Reader)）
- keyID は UUID 相当のランダム hex 文字列

### 3. ヘルパーメソッド

```go
// Issuer は Discovery の issuer と一致する URL を返す
func (m *MockIdP) Issuer() string

// AuthorizeURL は /authorize エンドポイントの URL を返す（go-oidc の AuthCodeURL と連携）
func (m *MockIdP) AuthorizeURL() string

// IssueCode は指定した subject/email に紐づく Authorization Code を直接生成する。
// テストで /authorize を経由せずにトークン取得フローを検証したい場合に使用。
func (m *MockIdP) IssueCode(subject, email, clientID, nonce string) string
```

### 4. OIDC Discovery エンドポイント

`GET /.well-known/openid-configuration` が返す JSON:

```json
{
  "issuer": "http://<server-host>",
  "authorization_endpoint": "http://<server-host>/authorize",
  "token_endpoint": "http://<server-host>/token",
  "jwks_uri": "http://<server-host>/jwks",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["ES256"],
  "scopes_supported": ["openid", "email", "profile"],
  "token_endpoint_auth_methods_supported": ["none"]
}
```

### 5. JWKS エンドポイント

`GET /jwks` が返す JSON:

```json
{
  "keys": [
    {
      "kty": "EC",
      "kid": "<keyID>",
      "crv": "P-256",
      "x": "<base64url>",
      "y": "<base64url>",
      "use": "sig",
      "alg": "ES256"
    }
  ]
}
```

**実装上の注意**: P-256 座標 (x, y) は `math/big.Int.Bytes()` の戻り値を **32バイト固定長にゼロパディング** してから `base64.RawURLEncoding.EncodeToString` すること。パディングが欠けると go-oidc が JWK 解析に失敗する。

```go
func padTo32(b []byte) []byte {
    padded := make([]byte, 32)
    copy(padded[32-len(b):], b)
    return padded
}
```

**keyID 生成**: `crypto/rand` を使ってランダムバイトを生成し hex エンコードすること（`math/rand` は不可）。

### 6. Authorization エンドポイント

`GET /authorize?response_type=code&client_id=...&redirect_uri=...&state=...&nonce=...`

1. `code` をランダム生成（hex 16バイト）
2. `codeEntry{subject, email, nonce, clientID}` をメモリに保存
3. `redirect_uri?code=<code>&state=<state>` にリダイレクト

subject・email はクエリパラメータ `subject` / `email` で指定可能（未指定時はデフォルト値）:
- subject: `"test-user-id"`
- email: `"test@example.com"`

### 7. Token エンドポイント

`POST /token` (application/x-www-form-urlencoded):
- `grant_type=authorization_code`
- `code=<code>`
- `redirect_uri=<redirect_uri>`
- `client_id=<client_id>`
- (PKCE) `code_verifier=<verifier>` ※ M08 では検証省略、M11 以降で本格対応

処理:
1. `code` を検索、なければ 400 エラー
2. ID Token (JWT ES256) を発行:
   - `iss`: issuer
   - `sub`: `codeEntry.subject`
   - `aud`: `codeEntry.clientID`
   - `email`: `codeEntry.email`
   - `nonce`: `codeEntry.nonce`
   - `iat`: now
   - `exp`: now + 1h
3. `{"access_token": "<opaque>", "token_type": "Bearer", "id_token": "<jwt>", "expires_in": 3600}` を返す
4. 発行済みコードをメモリから削除（一回使い切り）

---

## TDD 設計（Red → Green → Refactor）

### Red フェーズ: テスト先行記述

```
testutil/mock_idp_test.go に以下のテストを先に書く:
```

#### テスト1: Discovery Document

```go
func TestMockIdP_Discovery(t *testing.T) {
    m := NewMockIdP(t)
    resp, err := http.Get(m.Issuer() + "/.well-known/openid-configuration")
    // status 200, issuer 一致, authorization_endpoint 含む
}
```

#### テスト2: JWKS

```go
func TestMockIdP_JWKS(t *testing.T) {
    m := NewMockIdP(t)
    resp, err := http.Get(m.Issuer() + "/jwks")
    // status 200, keys 配列に1件, kty=EC, alg=ES256
}
```

#### テスト3: Authorization → Token フロー（コアフロー）

```go
func TestMockIdP_AuthFlow(t *testing.T) {
    m := NewMockIdP(t)
    // 1. /authorize にリダイレクトなしでリクエスト（redirect_uri にテストサーバーを使う）
    // 2. レスポンスの Location ヘッダーから code 取得
    // 3. /token に POST
    // 4. id_token を ES256 で検証、claims 確認
}
```

#### テスト4: 無効な code でトークン要求 → 400

```go
func TestMockIdP_InvalidCode(t *testing.T) {
    m := NewMockIdP(t)
    // /token に存在しない code → 400
}
```

#### テスト5: go-oidc 互換性確認

```go
func TestMockIdP_OIDCCompatibility(t *testing.T) {
    m := NewMockIdP(t)
    // go-oidc の NewProvider(ctx, m.Issuer()) が成功する
    // (go-oidc を依存に追加した後のテスト)
}
```

> **注意**: M08 時点では `go-oidc` は go.mod に未追加。
> テスト5は M10 でスキップ解除する。それまでは `t.Skip` でマーク。

---

## 依存ライブラリ

| ライブラリ | 用途 | 追加要否 |
|-----------|------|---------|
| `crypto/ecdsa` | ES256 鍵生成・署名 | 標準ライブラリ |
| `crypto/elliptic` | P-256 曲線 | 標準ライブラリ |
| `crypto/rand` | ランダム生成 | 標準ライブラリ |
| `encoding/json` | JSON シリアライズ | 標準ライブラリ |
| `math/big` | JWK の x/y 座標 | 標準ライブラリ |
| `net/http/httptest` | テストサーバー | 標準ライブラリ |
| `github.com/golang-jwt/jwt/v5` | JWT 発行 | **既存依存** |
| `go-oidc` | M10 で利用（M08 では未使用） | M10 で追加 |

**追加 go.mod 依存: なし**（golang-jwt/jwt/v5 は既存）

---

## ファイル構成

```
testutil/
  doc.go           # 既存（変更なし）
  mock_idp.go      # 新規作成
  mock_idp_test.go # 新規作成
```

---

## 実装ステップ

### Step 1: テスト先行（Red）
1. `testutil/mock_idp_test.go` を作成
2. `NewMockIdP`, Discovery, JWKS, AuthFlow, InvalidCode の各テストを記述
3. `go test ./testutil/...` → コンパイルエラー（Red 確認）

### Step 2: 最小実装（Green）
1. `testutil/mock_idp.go` を作成
2. `MockIdP` 構造体・コンストラクタを実装
3. 各エンドポイントハンドラーを実装
4. `go test -race ./testutil/...` → 全 GREEN 確認

### Step 3: リファクタリング（Refactor）
1. ハンドラーをメソッドに分離（`handleDiscovery`, `handleJWKS`, `handleAuthorize`, `handleToken`）
2. エラーレスポンスをヘルパー関数に共通化
3. `go test -race ./...` → 全 GREEN 確認

---

## リスク評価

| リスク | 影響度 | 対策 |
|--------|--------|------|
| JWT 署名アルゴリズムの不整合 | 高 | golang-jwt の ES256 SigningMethod を明示指定 |
| JWK の x/y 座標エンコード誤り | 高 | `base64.RawURLEncoding` を使用、テストで検証 |
| httptest.Server の URL が固定でない | 低 | `m.Server.URL` を動的取得し Discovery に反映 |
| code の並行アクセス | 中 | `sync.Mutex` で保護 |
| go-oidc の Discovery キャッシュ | 中 | M10 実装時に context timeout を設定 |

---

## 完了条件

- [ ] `go test -race ./testutil/...` 全 GREEN
- [ ] `go test -race ./...` 全 GREEN（既存テストに影響なし）
- [ ] Discovery / JWKS / AuthFlow / InvalidCode の各テストが通る
- [ ] `git commit` 済み: `feat(testutil): M08 モック IdP を TDD で実装`
- [ ] ロードマップ M08 チェックボックスを `[x]` に更新
