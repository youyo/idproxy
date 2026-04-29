// Package redis は idproxy.Store の Redis 実装を提供する。
//
// 用途: 汎用分散 KV による複数インスタンス間状態共有。go-redis v9 を使用。
//
// 使い方:
//
//	s, err := redisstore.New(redisstore.Options{Addr: "localhost:6379"})
//	if err != nil { ... }
//	defer s.Close()
//	cfg.Store = s
package redis

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/youyo/idproxy"
)

//go:embed consume.lua
var consumeLuaSource string

// コンパイル時にインターフェース実装を保証する。
var _ idproxy.Store = (*Store)(nil)

// Options は Store 生成時のパラメータ。
type Options struct {
	// Addr は Redis サーバーのホスト:ポート（例: "localhost:6379"）
	Addr string
	// Password は Redis 認証パスワード（任意）
	Password string
	// DB は使用する Redis DB 番号（0 はデフォルト）
	DB int
	// TLS が true の場合は TLS で接続する
	TLS bool
	// KeyPrefix は全キーに付与するプレフィックス（例: "idproxy:"）。空なら付与しない
	KeyPrefix string
}

// Store は Redis ベースの idproxy.Store 実装。
type Store struct {
	client    redis.UniversalClient
	prefix    string
	consume   *redis.Script
	closeOnce sync.Once
	closeErr  error
}

// New は Options から Store を生成する。生成後の Ping で疎通確認も行う。
func New(opts Options) (*Store, error) {
	ro := &redis.Options{
		Addr:     opts.Addr,
		Password: opts.Password,
		DB:       opts.DB,
	}
	if opts.TLS {
		ro.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	c := redis.NewClient(ro)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Ping(ctx).Err(); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("redis: ping: %w", err)
	}
	return NewWithClient(c, opts.KeyPrefix), nil
}

// NewWithClient は既存の redis.UniversalClient を使う Store を生成する（テスト用途）。
// 渡された client の Close は Store.Close() が呼び出す。
func NewWithClient(client redis.UniversalClient, keyPrefix string) *Store {
	return &Store{
		client:  client,
		prefix:  keyPrefix,
		consume: redis.NewScript(consumeLuaSource),
	}
}

func (s *Store) k(ns, id string) string {
	return s.prefix + ns + ":" + id
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

// --- Client（TTL なし）---

func (s *Store) SetClient(ctx context.Context, clientID string, data *idproxy.ClientData) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("redis: marshal client: %w", err)
	}
	if err := s.client.Set(ctx, s.k("client", clientID), b, 0).Err(); err != nil {
		return fmt.Errorf("redis: set client: %w", err)
	}
	return nil
}

func (s *Store) GetClient(ctx context.Context, clientID string) (*idproxy.ClientData, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := s.client.Get(ctx, s.k("client", clientID)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis: get client: %w", err)
	}
	var c idproxy.ClientData
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("redis: unmarshal client: %w", err)
	}
	return &c, nil
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

// ConsumeRefreshToken は Lua script で GET → Used 判定 → SET を atomic に行う。
func (s *Store) ConsumeRefreshToken(ctx context.Context, id string) (*idproxy.RefreshTokenData, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := s.k("refreshtoken", id)

	// 元値を読み出して Used=true 版を準備する（marshal は事前に Go 側で行う）
	rawCurrent, err := s.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis: consume read: %w", err)
	}

	var v idproxy.RefreshTokenData
	if err := json.Unmarshal(rawCurrent, &v); err != nil {
		return nil, fmt.Errorf("redis: unmarshal: %w", err)
	}
	usedCopy := v
	usedCopy.Used = true
	usedJSON, err := json.Marshal(&usedCopy)
	if err != nil {
		return nil, fmt.Errorf("redis: marshal: %w", err)
	}

	// 残り TTL を取得（PTTL は ms）。-1 は永続、-2 は無し
	pttl, err := s.client.PTTL(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: pttl: %w", err)
	}
	ttlMs := int64(0)
	if pttl > 0 {
		ttlMs = pttl.Milliseconds()
	}

	res, err := s.consume.Run(ctx, s.client, []string{key},
		time.Now().UnixMilli(), string(usedJSON), ttlMs).Slice()
	if err != nil {
		return nil, fmt.Errorf("redis: consume run: %w", err)
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("redis: consume: empty result")
	}
	tag, _ := res[0].(string)
	switch tag {
	case "notfound":
		return nil, nil
	case "replay":
		return &v, idproxy.ErrRefreshTokenAlreadyConsumed
	case "ok":
		return &usedCopy, nil
	default:
		return nil, fmt.Errorf("redis: consume: unknown tag %q", tag)
	}
}

// --- FamilyRevocation ---

func (s *Store) SetFamilyRevocation(ctx context.Context, familyID string, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.client.Set(ctx, s.k("familyrevoked", familyID), "1", ttl).Err(); err != nil {
		return fmt.Errorf("redis: set family revocation: %w", err)
	}
	return nil
}

func (s *Store) IsFamilyRevoked(ctx context.Context, familyID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	n, err := s.client.Exists(ctx, s.k("familyrevoked", familyID)).Result()
	if err != nil {
		return false, fmt.Errorf("redis: is family revoked: %w", err)
	}
	return n > 0, nil
}

// --- Cleanup / Close ---

// Cleanup は Redis では native TTL に委譲するため何もしない（no-op）。
func (s *Store) Cleanup(ctx context.Context) error {
	return ctx.Err()
}

// Close は内部の redis.Client を閉じる。冪等（sync.Once で保護）。
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = s.client.Close()
	})
	return s.closeErr
}

// --- 内部ヘルパー ---

func (s *Store) setJSON(ctx context.Context, ns, id string, v any, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("redis: marshal %s: %w", ns, err)
	}
	// ttl <= 0 の場合 native TTL では即時削除されないので、ここで明示的に削除して
	// memory store の挙動（即時 expired）と揃える。
	if ttl <= 0 {
		// 期限切れ相当 → 短い PEXPIRE を設定
		if err := s.client.Set(ctx, s.k(ns, id), b, time.Millisecond).Err(); err != nil {
			return fmt.Errorf("redis: set %s: %w", ns, err)
		}
		return nil
	}
	if err := s.client.Set(ctx, s.k(ns, id), b, ttl).Err(); err != nil {
		return fmt.Errorf("redis: set %s: %w", ns, err)
	}
	return nil
}

func (s *Store) getJSON(ctx context.Context, ns, id string, dst any) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	raw, err := s.client.Get(ctx, s.k(ns, id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("redis: get %s: %w", ns, err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return false, fmt.Errorf("redis: unmarshal %s: %w", ns, err)
	}
	return true, nil
}

func (s *Store) del(ctx context.Context, ns, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.client.Del(ctx, s.k(ns, id)).Err(); err != nil {
		return fmt.Errorf("redis: del %s: %w", ns, err)
	}
	return nil
}
