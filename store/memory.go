package store

import (
	"context"
	"sync"
	"time"

	"github.com/youyo/idproxy"
)

const defaultCleanupInterval = 5 * time.Minute

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
	mu           sync.RWMutex
	sessions     map[string]*memoryEntry[idproxy.Session]
	authCodes    map[string]*memoryEntry[idproxy.AuthCodeData]
	accessTokens map[string]*memoryEntry[idproxy.AccessTokenData]
	stopCh       chan struct{}
	closeOnce    sync.Once
}

// NewMemoryStore は新しい MemoryStore を生成し、バックグラウンドクリーンアップ goroutine を起動する。
func NewMemoryStore() *MemoryStore {
	return newMemoryStoreWithInterval(defaultCleanupInterval)
}

// newMemoryStoreWithInterval は指定した interval でクリーンアップ goroutine を起動する。
// interval が 0 以下の場合は goroutine を起動しない（テスト用途）。
func newMemoryStoreWithInterval(interval time.Duration) *MemoryStore {
	m := &MemoryStore{
		sessions:     make(map[string]*memoryEntry[idproxy.Session]),
		authCodes:    make(map[string]*memoryEntry[idproxy.AuthCodeData]),
		accessTokens: make(map[string]*memoryEntry[idproxy.AccessTokenData]),
		stopCh:       make(chan struct{}),
	}
	if interval > 0 {
		go m.cleanupLoop(interval)
	}
	return m
}

// cleanupLoop は指定した interval で Cleanup を定期呼び出しする。
// stopCh がクローズされると終了する。
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

// --- AuthCode CRUD ---

// SetAuthCode は認可コードを保存する。同一コードが存在する場合は上書きする。
func (m *MemoryStore) SetAuthCode(ctx context.Context, code string, data *idproxy.AuthCodeData, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.authCodes[code] = &memoryEntry[idproxy.AuthCodeData]{
		value:     data,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

// GetAuthCode は認可コードを取得する。
// 存在しない場合または期限切れの場合は nil, nil を返す。
func (m *MemoryStore) GetAuthCode(ctx context.Context, code string) (*idproxy.AuthCodeData, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, ok := m.authCodes[code]
	if !ok {
		return nil, nil
	}
	if entry.isExpired() {
		return nil, nil
	}
	return entry.value, nil
}

// DeleteAuthCode は認可コードを削除する。存在しない code の削除はエラーにならない（冪等）。
func (m *MemoryStore) DeleteAuthCode(ctx context.Context, code string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.authCodes, code)
	return nil
}

// --- AccessToken CRUD ---

// SetAccessToken はアクセストークンを保存する。同一 JTI が存在する場合は上書きする。
func (m *MemoryStore) SetAccessToken(ctx context.Context, jti string, data *idproxy.AccessTokenData, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.accessTokens[jti] = &memoryEntry[idproxy.AccessTokenData]{
		value:     data,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

// GetAccessToken はアクセストークンを取得する。
// 存在しない場合または期限切れの場合は nil, nil を返す。
func (m *MemoryStore) GetAccessToken(ctx context.Context, jti string) (*idproxy.AccessTokenData, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, ok := m.accessTokens[jti]
	if !ok {
		return nil, nil
	}
	if entry.isExpired() {
		return nil, nil
	}
	return entry.value, nil
}

// DeleteAccessToken はアクセストークンを削除する。存在しない JTI の削除はエラーにならない（冪等）。
func (m *MemoryStore) DeleteAccessToken(ctx context.Context, jti string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.accessTokens, jti)
	return nil
}

// Cleanup は全マップを走査し、期限切れエントリを削除する。
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

// Close はバックグラウンドクリーンアップ goroutine を停止する。
// 二重呼び出しは安全（sync.Once で保護）。
func (m *MemoryStore) Close() error {
	m.closeOnce.Do(func() {
		close(m.stopCh)
	})
	return nil
}
