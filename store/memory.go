package store

import (
	"context"
	"sync"
	"time"

	"github.com/youyo/idproxy"
)

// コンパイル時にインターフェース実装を保証する。
var _ idproxy.Store = (*MemoryStore)(nil)

// memoryEntry は TTL 付きのエントリをラップするジェネリック型。
type memoryEntry[T any] struct {
	value     *T
	expiresAt time.Time
}

// isExpired はエントリが期限切れかどうかを判定する。
func (e *memoryEntry[T]) isExpired() bool {
	return !e.expiresAt.IsZero() && time.Now().After(e.expiresAt)
}

// MemoryStore はインメモリの Store 実装。
// シングルインスタンス環境とテスト用途に適する。
type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*memoryEntry[idproxy.Session]
}

// NewMemoryStore は新しい MemoryStore を生成する。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]*memoryEntry[idproxy.Session]),
	}
}

// SetSession はセッションを保存する。同一 ID が存在する場合は上書きする。
func (m *MemoryStore) SetSession(ctx context.Context, id string, session *idproxy.Session, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions[id] = &memoryEntry[idproxy.Session]{
		value:     session,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

// GetSession はセッションを取得する。
// 存在しない場合または期限切れの場合は nil, nil を返す。
func (m *MemoryStore) GetSession(ctx context.Context, id string) (*idproxy.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, ok := m.sessions[id]
	if !ok {
		return nil, nil
	}
	if entry.isExpired() {
		return nil, nil
	}
	return entry.value, nil
}

// DeleteSession はセッションを削除する。存在しない ID の削除はエラーにならない（冪等）。
func (m *MemoryStore) DeleteSession(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessions, id)
	return nil
}

// --- 以下は M05/M06 で実装するスタブ ---

// SetAuthCode はスタブ実装。M05 で完全実装する。
func (m *MemoryStore) SetAuthCode(_ context.Context, _ string, _ *idproxy.AuthCodeData, _ time.Duration) error {
	return nil
}

// GetAuthCode はスタブ実装。M05 で完全実装する。
func (m *MemoryStore) GetAuthCode(_ context.Context, _ string) (*idproxy.AuthCodeData, error) {
	return nil, nil
}

// DeleteAuthCode はスタブ実装。M05 で完全実装する。
func (m *MemoryStore) DeleteAuthCode(_ context.Context, _ string) error {
	return nil
}

// SetAccessToken はスタブ実装。M05 で完全実装する。
func (m *MemoryStore) SetAccessToken(_ context.Context, _ string, _ *idproxy.AccessTokenData, _ time.Duration) error {
	return nil
}

// GetAccessToken はスタブ実装。M05 で完全実装する。
func (m *MemoryStore) GetAccessToken(_ context.Context, _ string) (*idproxy.AccessTokenData, error) {
	return nil, nil
}

// DeleteAccessToken はスタブ実装。M05 で完全実装する。
func (m *MemoryStore) DeleteAccessToken(_ context.Context, _ string) error {
	return nil
}

// Cleanup はスタブ実装。M06 で完全実装する。
func (m *MemoryStore) Cleanup(_ context.Context) error {
	return nil
}

// Close はスタブ実装。M06 で完全実装する。
func (m *MemoryStore) Close() error {
	return nil
}
