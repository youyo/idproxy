// Package momento は idproxy.Store の Momento 実装を提供する。
//
// 用途: Momento Serverless Cache を使った分散環境向けの状態共有。
// Momento は AWS / GCP / Azure の各リージョンで利用可能なマネージド KV サービス。
//
// CAS 戦略:
//   ConsumeRefreshToken は SetIfEqual（Momento ネイティブの CAS）を使用して
//   replay 検知を atomic に行う。Redis の Lua script や DynamoDB の
//   ConditionExpression と同等の保証を持つ。
//
// 使い方:
//
//	s, err := momentostore.New(momentostore.Options{
//	    AuthToken:  os.Getenv("MOMENTO_AUTH_TOKEN"),
//	    CacheName:  "idproxy",
//	    DefaultTTL: 24 * time.Hour, // Client 等 TTL なし扱いのキー用上限
//	})
//	if err != nil { ... }
//	defer s.Close()
package momento

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/momentohq/client-sdk-go/auth"
	"github.com/momentohq/client-sdk-go/config"
	"github.com/momentohq/client-sdk-go/momento"
	"github.com/momentohq/client-sdk-go/responses"
	"github.com/youyo/idproxy"
)

// コンパイル時にインターフェース実装を保証する。
var _ idproxy.Store = (*Store)(nil)

// Backend は Momento CacheClient のうち本パッケージで使う最小サブセット。
// テストでは in-memory フェイクを差し込む。
type Backend interface {
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Get(ctx context.Context, key string) ([]byte, bool, error)
	Delete(ctx context.Context, key string) error
	// SetIfEqual は現在値が equal と一致する場合のみ value で上書きする。
	// 一致しない or キー無しの場合は (false, nil)。
	SetIfEqual(ctx context.Context, key string, value, equal []byte, ttl time.Duration) (bool, error)
	Close() error
}

// Options は Store の生成パラメータ。
type Options struct {
	// AuthToken は Momento の認証トークン
	AuthToken string
	// CacheName は使用するキャッシュ名（事前作成済みであること）
	CacheName string
	// DefaultTTL は Set 時の上限 TTL。Client（TTL なし）はこれで保存する。
	// 未指定時は 24 時間。
	DefaultTTL time.Duration
	// KeyPrefix は全キーに付与するプレフィックス（任意）
	KeyPrefix string
}

// Store は Momento ベースの idproxy.Store 実装。
type Store struct {
	backend    Backend
	prefix     string
	defaultTTL time.Duration
	closeOnce  sync.Once
}

// New は Options から Store を生成する。
func New(opts Options) (*Store, error) {
	if opts.AuthToken == "" {
		return nil, errors.New("momento: AuthToken is required")
	}
	if opts.CacheName == "" {
		return nil, errors.New("momento: CacheName is required")
	}
	credProvider, err := auth.NewStringMomentoTokenProvider(opts.AuthToken)
	if err != nil {
		return nil, fmt.Errorf("momento: token provider: %w", err)
	}
	defaultTTL := opts.DefaultTTL
	if defaultTTL <= 0 {
		defaultTTL = 24 * time.Hour
	}
	cfg := config.LaptopLatest()
	client, err := momento.NewCacheClient(cfg, credProvider, defaultTTL)
	if err != nil {
		return nil, fmt.Errorf("momento: new client: %w", err)
	}
	be := &sdkBackend{client: client, cacheName: opts.CacheName}
	return NewWithBackend(be, opts.KeyPrefix, defaultTTL), nil
}

// NewWithBackend は Backend 実装を注入して Store を生成する（テスト用途）。
func NewWithBackend(b Backend, keyPrefix string, defaultTTL time.Duration) *Store {
	if defaultTTL <= 0 {
		defaultTTL = 24 * time.Hour
	}
	return &Store{
		backend:    b,
		prefix:     keyPrefix,
		defaultTTL: defaultTTL,
	}
}

func (s *Store) k(ns, id string) string { return s.prefix + ns + ":" + id }

// effectiveTTL は ttl <= 0 なら最小値 1ms（即時期限切れ相当）を返し、
// それ以外はそのまま返す。
func effectiveTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return time.Millisecond
	}
	return ttl
}

// --- Session ---

func (s *Store) SetSession(ctx context.Context, id string, sess *idproxy.Session, ttl time.Duration) error {
	return s.setJSON(ctx, "session", id, sess, ttl)
}
func (s *Store) GetSession(ctx context.Context, id string) (*idproxy.Session, error) {
	var v idproxy.Session
	ok, err := s.getJSON(ctx, "session", id, &v)
	if err != nil || !ok {
		return nil, err
	}
	return &v, nil
}
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	return s.del(ctx, "session", id)
}

// --- AuthCode ---

func (s *Store) SetAuthCode(ctx context.Context, code string, data *idproxy.AuthCodeData, ttl time.Duration) error {
	return s.setJSON(ctx, "authcode", code, data, ttl)
}
func (s *Store) GetAuthCode(ctx context.Context, code string) (*idproxy.AuthCodeData, error) {
	var v idproxy.AuthCodeData
	ok, err := s.getJSON(ctx, "authcode", code, &v)
	if err != nil || !ok {
		return nil, err
	}
	return &v, nil
}
func (s *Store) DeleteAuthCode(ctx context.Context, code string) error {
	return s.del(ctx, "authcode", code)
}

// --- AccessToken ---

func (s *Store) SetAccessToken(ctx context.Context, jti string, data *idproxy.AccessTokenData, ttl time.Duration) error {
	return s.setJSON(ctx, "accesstoken", jti, data, ttl)
}
func (s *Store) GetAccessToken(ctx context.Context, jti string) (*idproxy.AccessTokenData, error) {
	var v idproxy.AccessTokenData
	ok, err := s.getJSON(ctx, "accesstoken", jti, &v)
	if err != nil || !ok {
		return nil, err
	}
	return &v, nil
}
func (s *Store) DeleteAccessToken(ctx context.Context, jti string) error {
	return s.del(ctx, "accesstoken", jti)
}

// --- Client ---

func (s *Store) SetClient(ctx context.Context, clientID string, data *idproxy.ClientData) error {
	// Momento は無期限 TTL に対応しないため defaultTTL を使う
	return s.setJSON(ctx, "client", clientID, data, s.defaultTTL)
}
func (s *Store) GetClient(ctx context.Context, clientID string) (*idproxy.ClientData, error) {
	var v idproxy.ClientData
	ok, err := s.getJSON(ctx, "client", clientID, &v)
	if err != nil || !ok {
		return nil, err
	}
	return &v, nil
}
func (s *Store) DeleteClient(ctx context.Context, clientID string) error {
	return s.del(ctx, "client", clientID)
}

// --- RefreshToken ---

func (s *Store) SetRefreshToken(ctx context.Context, id string, data *idproxy.RefreshTokenData, ttl time.Duration) error {
	return s.setJSON(ctx, "refreshtoken", id, data, ttl)
}
func (s *Store) GetRefreshToken(ctx context.Context, id string) (*idproxy.RefreshTokenData, error) {
	var v idproxy.RefreshTokenData
	ok, err := s.getJSON(ctx, "refreshtoken", id, &v)
	if err != nil || !ok {
		return nil, err
	}
	return &v, nil
}

// ConsumeRefreshToken は SetIfEqual で「現在値が Used=false 版と一致するなら Used=true に置換」を atomic に行う。
// 失敗 (不一致) は replay とみなす。
func (s *Store) ConsumeRefreshToken(ctx context.Context, id string) (*idproxy.RefreshTokenData, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := s.k("refreshtoken", id)
	current, ok, err := s.backend.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("momento: consume get: %w", err)
	}
	if !ok {
		return nil, nil
	}
	var v idproxy.RefreshTokenData
	if err := json.Unmarshal(current, &v); err != nil {
		return nil, fmt.Errorf("momento: consume unmarshal: %w", err)
	}
	if v.Used {
		return &v, idproxy.ErrRefreshTokenAlreadyConsumed
	}

	usedCopy := v
	usedCopy.Used = true
	usedJSON, err := json.Marshal(&usedCopy)
	if err != nil {
		return nil, fmt.Errorf("momento: marshal: %w", err)
	}

	// TTL 維持: Momento は SetIfEqual 時に新しい TTL が必須。
	// 元 TTL を取れない場合は defaultTTL で更新する（運用上 RT は数日〜数週なので defaultTTL=24h でも妥当）。
	swapped, err := s.backend.SetIfEqual(ctx, key, usedJSON, current, s.defaultTTL)
	if err != nil {
		return nil, fmt.Errorf("momento: setifequal: %w", err)
	}
	if !swapped {
		// 競合: 別ゴルーチンが先に Used=true に切替済み → replay
		// 値を再取得して FamilyID を返す
		again, _, _ := s.backend.Get(ctx, key)
		if len(again) > 0 {
			var v2 idproxy.RefreshTokenData
			if json.Unmarshal(again, &v2) == nil && v2.Used {
				return &v2, idproxy.ErrRefreshTokenAlreadyConsumed
			}
		}
		return &v, idproxy.ErrRefreshTokenAlreadyConsumed
	}
	return &usedCopy, nil
}

// --- FamilyRevocation ---

func (s *Store) SetFamilyRevocation(ctx context.Context, familyID string, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.backend.Set(ctx, s.k("familyrevoked", familyID), []byte("1"), effectiveTTL(ttl))
}

func (s *Store) IsFamilyRevoked(ctx context.Context, familyID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	_, ok, err := s.backend.Get(ctx, s.k("familyrevoked", familyID))
	if err != nil {
		return false, fmt.Errorf("momento: is family revoked: %w", err)
	}
	return ok, nil
}

// --- Cleanup / Close ---

// Cleanup は Momento では native TTL に委譲するため何もしない。
func (s *Store) Cleanup(ctx context.Context) error { return ctx.Err() }

func (s *Store) Close() error {
	var err error
	s.closeOnce.Do(func() {
		err = s.backend.Close()
	})
	return err
}

// --- 内部ヘルパー ---

func (s *Store) setJSON(ctx context.Context, ns, id string, v any, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("momento: marshal %s: %w", ns, err)
	}
	if err := s.backend.Set(ctx, s.k(ns, id), b, effectiveTTL(ttl)); err != nil {
		return fmt.Errorf("momento: set %s: %w", ns, err)
	}
	return nil
}

func (s *Store) getJSON(ctx context.Context, ns, id string, dst any) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	raw, ok, err := s.backend.Get(ctx, s.k(ns, id))
	if err != nil {
		return false, fmt.Errorf("momento: get %s: %w", ns, err)
	}
	if !ok {
		return false, nil
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return false, fmt.Errorf("momento: unmarshal %s: %w", ns, err)
	}
	return true, nil
}

func (s *Store) del(ctx context.Context, ns, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.backend.Delete(ctx, s.k(ns, id)); err != nil {
		return fmt.Errorf("momento: delete %s: %w", ns, err)
	}
	return nil
}

// --- sdkBackend: 実 Momento SDK ラッパー ---

type sdkBackend struct {
	client    momento.CacheClient
	cacheName string
}

func (b *sdkBackend) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	_, err := b.client.Set(ctx, &momento.SetRequest{
		CacheName: b.cacheName,
		Key:       momento.String(key),
		Value:     momento.Bytes(value),
		Ttl:       ttl,
	})
	return err
}

func (b *sdkBackend) Get(ctx context.Context, key string) ([]byte, bool, error) {
	resp, err := b.client.Get(ctx, &momento.GetRequest{
		CacheName: b.cacheName,
		Key:       momento.String(key),
	})
	if err != nil {
		return nil, false, err
	}
	switch r := resp.(type) {
	case *responses.GetHit:
		return r.ValueByte(), true, nil
	case *responses.GetMiss:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("momento: unexpected GetResponse %T", resp)
	}
}

func (b *sdkBackend) Delete(ctx context.Context, key string) error {
	_, err := b.client.Delete(ctx, &momento.DeleteRequest{
		CacheName: b.cacheName,
		Key:       momento.String(key),
	})
	return err
}

func (b *sdkBackend) SetIfEqual(ctx context.Context, key string, value, equal []byte, ttl time.Duration) (bool, error) {
	resp, err := b.client.SetIfEqual(ctx, &momento.SetIfEqualRequest{
		CacheName: b.cacheName,
		Key:       momento.String(key),
		Value:     momento.Bytes(value),
		Equal:     momento.Bytes(equal),
		Ttl:       ttl,
	})
	if err != nil {
		return false, err
	}
	switch resp.(type) {
	case *responses.SetIfEqualStored:
		return true, nil
	case *responses.SetIfEqualNotStored:
		return false, nil
	default:
		return false, fmt.Errorf("momento: unexpected SetIfEqualResponse %T", resp)
	}
}

func (b *sdkBackend) Close() error {
	b.client.Close()
	return nil
}

// --- in-memory backend for tests ---

type memoryBackend struct {
	mu   sync.Mutex
	data map[string]memoryEntry
}

type memoryEntry struct {
	value     []byte
	expiresAt time.Time
}

// NewMemoryBackend は Backend のテスト用 in-memory 実装を返す。
func NewMemoryBackend() Backend {
	return &memoryBackend{data: make(map[string]memoryEntry)}
}

func (m *memoryBackend) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = memoryEntry{value: append([]byte(nil), value...), expiresAt: time.Now().Add(ttl)}
	return nil
}

func (m *memoryBackend) Get(_ context.Context, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.data[key]
	if !ok {
		return nil, false, nil
	}
	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		delete(m.data, key)
		return nil, false, nil
	}
	return append([]byte(nil), e.value...), true, nil
}

func (m *memoryBackend) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *memoryBackend) SetIfEqual(_ context.Context, key string, value, equal []byte, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.data[key]
	if !ok {
		return false, nil
	}
	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		delete(m.data, key)
		return false, nil
	}
	if !bytes.Equal(e.value, equal) {
		return false, nil
	}
	m.data[key] = memoryEntry{value: append([]byte(nil), value...), expiresAt: time.Now().Add(ttl)}
	return true, nil
}

func (m *memoryBackend) Close() error { return nil }
