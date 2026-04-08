# M06: MemoryStore - クリーンアップ 実装計画

## 概要

`MemoryStore` の `Cleanup()` と `Close()` スタブを完全実装する。
TTL 期限切れエントリの能動的削除とバックグラウンド goroutine による自動クリーンアップを提供する。

## 現状確認

- `store/memory.go` に `Cleanup()` と `Close()` がスタブとして存在（L197-204）
- `MemoryStore` は `sessions`, `authCodes`, `accessTokens` の 3 マップを保有
- 単一 `sync.RWMutex` で保護
- `memoryEntry[T]` の `isExpired()` メソッド実装済み（Lazy TTL）
- goroutine / ticker フィールドは現時点で存在しない

## 実装スコープ

### 1. `Cleanup(ctx context.Context) error`

全 3 マップを走査し、`isExpired()` が true のエントリを削除する。

```go
func (m *MemoryStore) Cleanup(_ context.Context) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    for k, e := range m.sessions {
        if e.isExpired() {
            delete(m.sessions, k)
        }
    }
    for k, e := range m.authCodes {
        if e.isExpired() {
            delete(m.authCodes, k)
        }
    }
    for k, e := range m.accessTokens {
        if e.isExpired() {
            delete(m.accessTokens, k)
        }
    }
    return nil
}
```

### 2. バックグラウンド goroutine（5分間隔 Ticker）

`MemoryStore` に `stopCh chan struct{}` フィールドを追加し、
`NewMemoryStore()` 内でバックグラウンド goroutine を起動する。

```go
type MemoryStore struct {
    mu           sync.RWMutex
    sessions     map[string]*memoryEntry[idproxy.Session]
    authCodes    map[string]*memoryEntry[idproxy.AuthCodeData]
    accessTokens map[string]*memoryEntry[idproxy.AccessTokenData]
    stopCh       chan struct{}
}

func NewMemoryStore() *MemoryStore {
    m := &MemoryStore{
        sessions:     make(map[string]*memoryEntry[idproxy.Session]),
        authCodes:    make(map[string]*memoryEntry[idproxy.AuthCodeData]),
        accessTokens: make(map[string]*memoryEntry[idproxy.AccessTokenData]),
        stopCh:       make(chan struct{}),
    }
    go m.cleanupLoop(5 * time.Minute)
    return m
}

func (m *MemoryStore) cleanupLoop(interval time.Duration) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            _ = m.Cleanup(context.Background())
        case <-m.stopCh:
            return
        }
    }
}
```

### 3. `Close() error`

`stopCh` をクローズして goroutine を停止する。二重呼び出し安全のため `sync.Once` を使用する。

```go
type MemoryStore struct {
    // ... 既存フィールド ...
    stopCh   chan struct{}
    closeOnce sync.Once
}

func (m *MemoryStore) Close() error {
    m.closeOnce.Do(func() {
        close(m.stopCh)
    })
    return nil
}
```

## TDD 設計（Red → Green → Refactor）

### Red フェーズ: 失敗するテストを先に書く

`store/memory_test.go` に以下のテストを追加する。

#### Test 1: `TestMemoryStore_Cleanup_RemovesExpiredSessions`
```go
func TestMemoryStore_Cleanup_RemovesExpiredSessions(t *testing.T) {
    ms := NewMemoryStore()
    ctx := context.Background()

    // 期限切れエントリを設定
    _ = ms.SetSession(ctx, "expired", testSession(), -time.Second)
    // 有効エントリを設定
    _ = ms.SetSession(ctx, "valid", testSession(), time.Hour)

    err := ms.Cleanup(ctx)
    if err != nil {
        t.Fatalf("Cleanup() error = %v", err)
    }

    // 期限切れは nil を返す（Lazy TTL と同等の挙動）
    got, _ := ms.GetSession(ctx, "expired")
    if got != nil {
        t.Error("expired session should be nil after Cleanup")
    }
    // 有効エントリは残る
    got, _ = ms.GetSession(ctx, "valid")
    if got == nil {
        t.Error("valid session should remain after Cleanup")
    }
}
```

#### Test 2: `TestMemoryStore_Cleanup_RemovesExpiredAuthCodes`
#### Test 3: `TestMemoryStore_Cleanup_RemovesExpiredAccessTokens`
#### Test 4: `TestMemoryStore_Cleanup_AllTypes` — 3 マップ同時検証
#### Test 5: `TestMemoryStore_Close_StopsGoroutine` — Close 後に Cleanup が走らないこと（ただし直接検証は困難のためリーク検出のみ）
#### Test 6: `TestMemoryStore_Close_Idempotent` — 二重 Close がパニックしないこと

### Green フェーズ: 最小限の実装

1. `MemoryStore` 構造体に `stopCh chan struct{}` と `closeOnce sync.Once` を追加
2. `NewMemoryStore()` で goroutine を起動
3. `Cleanup()` に全マップ走査ロジックを実装
4. `Close()` で `stopCh` をクローズ

### Refactor フェーズ: 整理

- `cleanupExpired[T]` ヘルパー関数でマップ走査を共通化する（DRY）
  - ただし Go のジェネリクスでマップを受け取る場合、型パラメータが必要になる点を考慮
  - 複雑になるなら 3 つのループを素直に並べる方が読みやすい（YAGNI）

## 実装ステップ

1. **テスト追加（Red）**
   - `store/memory_test.go` にクリーンアップテスト 6 本を追加
   - `go test ./...` が RED になることを確認

2. **構造体変更**
   - `MemoryStore` に `stopCh chan struct{}` と `closeOnce sync.Once` を追加

3. **`NewMemoryStore()` 変更**
   - `stopCh` 初期化
   - `cleanupLoop` goroutine 起動

4. **`cleanupLoop()` 追加**
   - `time.Ticker` で 5 分間隔
   - `stopCh` 受信で return

5. **`Cleanup()` 実装**
   - スタブを本実装に置き換え

6. **`Close()` 実装**
   - `sync.Once` で安全クローズ

7. **テスト確認（Green）**
   - `go test -race ./...` が全 GREEN

8. **Refactor**
   - コメント整備、不要な抽象化がないか確認

9. **コミット**
   - `feat(store): M06 MemoryStore - Cleanup と Close を TDD で実装`

## リスク評価

### リスク 1: テスト内での goroutine リーク
- **内容**: `NewMemoryStore()` がテストごとに goroutine を起動し、`Close()` を呼ばないとリークする
- **影響度**: 中（テスト実行は問題ないが `-race` で警告が出ることがある）
- **対策**: 全テストで `defer ms.Close()` を追加するか、テスト専用コンストラクタ `newMemoryStoreWithInterval(0)` を用意する
  - `0` または `math.MaxInt64` を interval に渡すと ticker は動かない
  - より シンプルな解: interval を外部から渡せる内部コンストラクタ `newMemoryStoreForTest()` を用意

### リスク 2: テスト内での時間依存
- **内容**: `time.Sleep` によるフラキーテスト
- **影響度**: 高
- **対策**: TTL に `-time.Second`（過去時刻）を設定することで即時期限切れ状態を作り、`Sleep` を使わない

### リスク 3: `Close()` 二重呼び出しによる panic
- **内容**: `close(ch)` を 2 回呼ぶと panic
- **影響度**: 高
- **対策**: `sync.Once` で保護する（計画に含み済み）

### リスク 4: Cleanup 中の書き込み競合
- **内容**: goroutine が Cleanup 中に Set/Delete が呼ばれる場合
- **影響度**: 高
- **対策**: `Cleanup()` 内で `m.mu.Lock()` を取得（計画に含み済み）。`-race` テストで確認

### リスク 5: Store インターフェースの変更
- **内容**: `idproxy.Store` に `Close()` が含まれていない可能性
- **影響度**: 低〜中
- **対策**: 実装前にインターフェース定義を確認する

## 完了条件

- [ ] `Cleanup()` が期限切れエントリを 3 マップ全てから削除する
- [ ] バックグラウンド goroutine が 5 分間隔で Cleanup を呼ぶ
- [ ] `Close()` が goroutine を停止する
- [ ] `Close()` の二重呼び出しが安全
- [ ] `go test -race ./...` が全 GREEN
- [ ] コミット完了

## ファイル変更一覧

| ファイル | 変更種別 | 内容 |
|---------|---------|------|
| `store/memory.go` | 修正 | Cleanup/Close 実装、構造体フィールド追加、cleanupLoop 追加 |
| `store/memory_test.go` | 修正 | クリーンアップテスト 6 本追加 |
