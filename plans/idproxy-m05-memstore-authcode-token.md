# M05: MemoryStore - AuthCode・AccessToken CRUD

## Meta
- milestone: M05
- depends_on: M04 (MemoryStore Session CRUD, memoryEntry ジェネリック型)
- produces: store/memory.go（拡張）, store/memory_test.go（拡張）
- status: planning

## 概要

`store/memory.go` の AuthCode・AccessToken スタブを完全実装に置き換える。
M04 で確立した `memoryEntry[T]` ジェネリック型 + `sync.RWMutex` + map パターンを踏襲し、
AuthCodeData と AccessTokenData の CRUD を TDD で追加する。

## 設計方針

### MemoryStore 拡張

```go
type MemoryStore struct {
    mu           sync.RWMutex
    sessions     map[string]*memoryEntry[idproxy.Session]
    authCodes    map[string]*memoryEntry[idproxy.AuthCodeData]    // M05 追加
    accessTokens map[string]*memoryEntry[idproxy.AccessTokenData] // M05 追加
}
```

コンストラクタ `NewMemoryStore()` も 2 フィールドの初期化を追加する。

### AuthCode / AccessToken の設計方針

M04 の Session CRUD と全く同じパターンを適用:

| 操作 | 動作 |
|------|------|
| Set | 上書き可（同一キーの2重書き込み可） |
| Get | 存在しない / 期限切れ → `nil, nil`（Lazy expiration） |
| Delete | 存在しない削除はエラーなし（冪等） |
| Context キャンセル | 先頭で `ctx.Err()` チェック → エラー返却 |

### AuthCode 固有の注意点

- `AuthCodeData.Used` フィールドがあるが、SetAuthCode/GetAuthCode は単純な CRUD のみ
  - Used フラグの更新はドメインロジック側（M08以降）で行う
  - MemoryStore は値をそのまま保存・返却するのみ
  - **TOCTOU 注意**: GetAuthCode → Used=true に変更 → SetAuthCode という操作は競合状態になりうる。
    これはドメインロジック側で atomic な Compare-And-Swap 操作として実装すべき。MemoryStore のスコープ外。
- キーは `code`（認可コード文字列）

### AccessToken 固有の注意点

- キーは `jti`（JWT ID）
- `AccessTokenData.Revoked` フィールドも単純に保存・返却するのみ

### エラー設計

Session CRUD と同一:
- Set: 重複上書き可、context キャンセルのみエラー
- Get: 不存在/期限切れ → nil, nil
- Delete: 冪等（不存在も OK）
- Context キャンセル → ctx.Err() を返す

### ロック戦略

M04 と同一:
- Set/Delete: `m.mu.Lock()` / `defer m.mu.Unlock()`
- Get: `m.mu.RLock()` / `defer m.mu.RUnlock()`

authCodes と accessTokens は sessions と同じ `m.mu` で保護する（ロック数を最小化）。

## TDD テスト設計（Red → Green → Refactor）

### Phase 1: Red（テスト先行）

`store/memory_test.go` に以下のテストを追加する（実装前に書いてコンパイルエラーを確認）:

#### AuthCode テスト

##### testAuthCodeData()
```go
func testAuthCodeData() *idproxy.AuthCodeData {
    now := time.Now()
    return &idproxy.AuthCodeData{
        Code:                "code-abc123",
        ClientID:            "client-001",
        RedirectURI:         "https://app.example.com/callback",
        CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        CodeChallengeMethod: "S256",
        Scopes:              []string{"openid", "profile"},
        User:                &idproxy.User{Email: "test@example.com", Subject: "sub-001"},
        CreatedAt:           now,
        ExpiresAt:           now.Add(10 * time.Minute),
    }
}
```

##### TestMemoryStore_SetGetAuthCode
- SetAuthCode → GetAuthCode で同一データが取得できる
- 主要フィールド（Code, ClientID, RedirectURI, Scopes, User）を検証

##### TestMemoryStore_GetAuthCode_NotFound
- 存在しない code → nil, nil

##### TestMemoryStore_GetAuthCode_Expired
- TTL 0 で Set → Get すると nil, nil

##### TestMemoryStore_SetAuthCode_Overwrite
- 同一 code で2回 Set → 最新の値が取得される

##### TestMemoryStore_DeleteAuthCode
- Set → Delete → Get で nil, nil

##### TestMemoryStore_DeleteAuthCode_NotFound
- 存在しない code の Delete → error なし

##### TestMemoryStore_SetAuthCode_ContextCanceled
- キャンセル済み ctx で Set → ctx.Err()

##### TestMemoryStore_GetAuthCode_ContextCanceled
- キャンセル済み ctx で Get → nil, ctx.Err()

##### TestMemoryStore_DeleteAuthCode_ContextCanceled
- キャンセル済み ctx で Delete → ctx.Err()

#### AccessToken テスト

##### testAccessTokenData()
```go
func testAccessTokenData() *idproxy.AccessTokenData {
    now := time.Now()
    return &idproxy.AccessTokenData{
        JTI:       "jti-xyz789",
        Subject:   "sub-001",
        Email:     "test@example.com",
        ClientID:  "client-001",
        Scopes:    []string{"openid", "profile"},
        IssuedAt:  now,
        ExpiresAt: now.Add(time.Hour),
        Revoked:   false,
    }
}
```

##### TestMemoryStore_SetGetAccessToken
- SetAccessToken → GetAccessToken で同一データが取得できる
- 主要フィールド（JTI, Subject, Email, ClientID, Scopes, Revoked）を検証

##### TestMemoryStore_GetAccessToken_NotFound
- 存在しない jti → nil, nil

##### TestMemoryStore_GetAccessToken_Expired
- TTL 0 で Set → Get すると nil, nil

##### TestMemoryStore_SetAccessToken_Overwrite
- 同一 jti で2回 Set → 最新の値が取得される

##### TestMemoryStore_DeleteAccessToken
- Set → Delete → Get で nil, nil

##### TestMemoryStore_DeleteAccessToken_NotFound
- 存在しない jti の Delete → error なし

##### TestMemoryStore_SetAccessToken_ContextCanceled
- キャンセル済み ctx で Set → ctx.Err()

##### TestMemoryStore_GetAccessToken_ContextCanceled
- キャンセル済み ctx で Get → nil, ctx.Err()

##### TestMemoryStore_DeleteAccessToken_ContextCanceled
- キャンセル済み ctx で Delete → ctx.Err()

#### 複合並行テスト

##### TestMemoryStore_Concurrent_AllTypes
- Session / AuthCode / AccessToken を混在させた goroutine 50本×3操作で race condition なし

### Phase 2: Green（最小限の実装）

1. `MemoryStore` に `authCodes` / `accessTokens` フィールドを追加
2. `NewMemoryStore()` でこれらを初期化
3. スタブの SetAuthCode/GetAuthCode/DeleteAuthCode を完全実装に置き換え
4. スタブの SetAccessToken/GetAccessToken/DeleteAccessToken を完全実装に置き換え

### Phase 3: Refactor

- コメント更新（スタブコメントを正式実装コメントに変更）
- セクションコメント `// --- 以下は M05/M06 で実装するスタブ ---` を整理
- 過剰な複雑性がないか確認

## 実装ステップ

1. `store/memory_test.go` にテストを追加（Red）
2. `go test ./store/...` でコンパイルエラーまたはテスト失敗を確認
3. `store/memory.go` の MemoryStore struct に authCodes / accessTokens を追加
4. `NewMemoryStore()` を更新
5. SetAuthCode / GetAuthCode / DeleteAuthCode を実装
6. SetAccessToken / GetAccessToken / DeleteAccessToken を実装
7. `go test -race ./...` で全 green を確認（Green）
8. コメント・ドキュメントを整理（Refactor）
9. `go test -race ./...` で再度 green を確認

## リスク評価

### リスク1: 単一 mutex による lock contention
- **影響**: 低（インメモリ、テスト用途、スループット要件なし）
- **軽減策**: M05 スコープでは許容。将来的に per-type mutex への分割は M07 以降で検討

### リスク2: Revoked フィールドの扱い
- **影響**: 低（単純な値保存なので混乱なし）
- **軽減策**: コメントで「リボケーション操作はドメインロジック側で行う」と明記

### リスク3: 既存テストの破壊
- **影響**: 低（NewMemoryStore の初期化変更は既存テストに影響しない）
- **軽減策**: `go test -race ./...` でフル検証

### リスク4: TTL=0 の挙動
- **影響**: 中（M04 では TTL=0 が即時期限切れとして機能することを検証済み）
- **軽減策**: M04 と同じ `isExpired()` ロジックを使用するため問題なし

## ファイル配置

```
store/
  memory.go       # 拡張: authCodes/accessTokens フィールド追加、スタブを完全実装に置き換え
  memory_test.go  # 拡張: AuthCode/AccessToken CRUD テスト追加
```

## Changelog
- 2026-04-09: 初版作成
