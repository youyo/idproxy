# M04: MemoryStore - Session CRUD

## Meta
- milestone: M04
- depends_on: M02 (Store interface, Session type)
- produces: store/memory.go, store/memory_test.go
- status: done

## 概要

`store/memory.go` に `MemoryStore` を実装する。M04 では Session CRUD のみを完全実装し、
AuthCode/AccessToken/Cleanup/Close は Store インターフェースを満たすためのスタブ（nil 返却）とする。

## 設計方針

### データ構造

```go
// memoryEntry は TTL 付きのエントリをラップするジェネリック型。
type memoryEntry[T any] struct {
    value     *T
    expiresAt time.Time
}

// MemoryStore はインメモリの Store 実装。
// シングルインスタンス環境とテスト用途に適する。
type MemoryStore struct {
    mu       sync.RWMutex
    sessions map[string]*memoryEntry[idproxy.Session]
    // authCodes, accessTokens は M05 で追加
}
```

### 選択: sync.RWMutex + map vs sync.Map

**sync.RWMutex + map を選択する理由:**
- TTL チェック付き Get は read-modify パターンで、sync.Map の atomic 操作メリットが薄い
- Cleanup() で全エントリ走査が必要 → sync.Map.Range() より map 走査のほうがシンプル
- 型安全性: ジェネリクスで型キャストが不要
- テストの予測可能性が高い

### TTL チェック

- `GetSession()` 時に `expiresAt` を確認し、期限切れなら `nil, nil` を返す（削除はしない）
- Get は Read ロックのみで完結させる（RWMutex アップグレード不要）
- 期限切れエントリの実際の削除は Cleanup()（M06）に委ねる
- Lazy expiration パターン（Get 時チェック）で M04 では十分

### エラー設計

- `SetSession`: key 重複は上書き（エラーなし）
- `GetSession`: 存在しない / 期限切れ → `nil, nil`（ErrNotFound は返さない）
- `DeleteSession`: 存在しないキーの削除はエラーなし（冪等）
- context キャンセル時は `ctx.Err()` を返す

### コンストラクタ

```go
func NewMemoryStore() *MemoryStore
```
- 引数なし。map を初期化して返す。
- *MemoryStore は idproxy.Store を実装する（コンパイル時アサーション付き）。

## Store インターフェース充足（スタブ）

M04 スコープ外のメソッドはスタブで実装:

```go
func (m *MemoryStore) SetAuthCode(ctx context.Context, code string, data *idproxy.AuthCodeData, ttl time.Duration) error { return nil }
func (m *MemoryStore) GetAuthCode(ctx context.Context, code string) (*idproxy.AuthCodeData, error) { return nil, nil }
func (m *MemoryStore) DeleteAuthCode(ctx context.Context, code string) error { return nil }
func (m *MemoryStore) SetAccessToken(ctx context.Context, jti string, data *idproxy.AccessTokenData, ttl time.Duration) error { return nil }
func (m *MemoryStore) GetAccessToken(ctx context.Context, jti string) (*idproxy.AccessTokenData, error) { return nil, nil }
func (m *MemoryStore) DeleteAccessToken(ctx context.Context, jti string) error { return nil }
func (m *MemoryStore) Cleanup(ctx context.Context) error { return nil }
func (m *MemoryStore) Close() error { return nil }
```

## TDD テスト設計

### テストケース一覧

#### TestNewMemoryStore
- コンストラクタが non-nil を返す
- Store インターフェースを実装する（型アサーション）

#### TestMemoryStore_SetGetSession
- Set → Get で同一セッションが取得できる
- セッションのフィールドが正しく保存されている

#### TestMemoryStore_GetSession_NotFound
- 存在しない ID → nil, nil

#### TestMemoryStore_GetSession_Expired
- TTL 0 or 負で Set → Get すると nil, nil（期限切れ）

#### TestMemoryStore_SetSession_Overwrite
- 同一 ID で2回 Set → 最新の値が取得される

#### TestMemoryStore_DeleteSession
- Set → Delete → Get で nil, nil

#### TestMemoryStore_DeleteSession_NotFound
- 存在しない ID の Delete → error なし

#### TestMemoryStore_SetSession_ContextCanceled
- キャンセル済みコンテキストで Set → ctx.Err()

#### TestMemoryStore_GetSession_ContextCanceled
- キャンセル済みコンテキストで Get → nil, ctx.Err()

#### TestMemoryStore_Concurrent
- 複数 goroutine で同時に Set/Get/Delete → race condition なし（-race フラグで検証）

## 実装順序

1. **Red**: store/memory_test.go にテストケースを全て書く（コンパイルエラー）
2. **Green**: store/memory.go に最小限の実装を書いてテストを通す
3. **Refactor**: コードを整理、コメント追加
4. **Verify**: `go test -race ./store/...` で全テスト green + race detector pass

## ファイル配置

```
store/
  doc.go          # 既存
  memory.go       # 新規: MemoryStore 実装
  memory_test.go  # 新規: テスト
```

## Changelog
- 2026-04-09: 初版作成
