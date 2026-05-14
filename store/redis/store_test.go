package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/youyo/idproxy"
	"github.com/youyo/idproxy/store/storetest"
)

func TestStore_Conformance(t *testing.T) {
	storetest.RunConformance(t, func(t *testing.T) (idproxy.Store, func()) {
		mr := miniredis.RunT(t)
		// miniredis の TTL は実時間と連動しないので、バックグラウンドで一定間隔ごとに
		// 時計を進めることで Sleep ベースの期限切れテストを通す。
		stop := make(chan struct{})
		go func() {
			ticker := time.NewTicker(2 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					mr.FastForward(2 * time.Millisecond)
				}
			}
		}()

		client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
		s := NewWithClient(client, "test:")
		return s, func() {
			close(stop)
			_ = s.Close()
			mr.Close()
		}
	})
}

// --- M23 Phase B-3: ClientOwnership Option テスト ---

// S1: デフォルト（Option 無指定）では Store.Close() が client.Close() を呼ぶ。
// Close 後に client での操作がエラーになることで観測する。
func TestRedisStore_Close_DefaultOwnsClient(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})

	s := NewWithClient(client, "test:")
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Close 後の client は使えなくなっているはず
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := client.Ping(ctx).Err()
	if err == nil {
		t.Error("expected error pinging client after Store.Close() with default ownership; got nil")
	}
}

// S2: WithClientOwnership(false) を渡した場合、Close() は client.Close() を呼ばない。
// Close 後も client.Ping が成功すれば OK。
func TestRedisStore_Close_OwnsClientFalse(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	defer func() {
		_ = client.Close()
	}()

	s := NewWithClient(client, "test:", WithClientOwnership(false))
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Close 後でも client は使える
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Errorf("client should still be usable after Store.Close() with WithClientOwnership(false), got: %v", err)
	}
}

// S3: Option 順序を入れ替えても期待状態が保たれる。
func TestRedisStore_OptionOrderIndependent(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	defer func() {
		_ = client.Close()
	}()

	// 同じ Option を 2 回（false の後 true）→ 最後に評価された true が勝つ。
	s := NewWithClient(client, "test:", WithClientOwnership(false), WithClientOwnership(true))
	if !s.ownsClient {
		t.Errorf("expected ownsClient=true after WithClientOwnership(false), WithClientOwnership(true)")
	}

	// 逆順
	client2 := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	defer func() {
		_ = client2.Close()
	}()
	s2 := NewWithClient(client2, "test:", WithClientOwnership(true), WithClientOwnership(false))
	if s2.ownsClient {
		t.Errorf("expected ownsClient=false after WithClientOwnership(true), WithClientOwnership(false)")
	}
}

// 追加: 既存呼び出し（Option 無指定）が引き続き有効である回帰確認。
func TestRedisStore_BackwardCompatible_NewWithClient(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})

	// 既存の 2 引数シグネチャでコンパイル・動作することを確認
	s := NewWithClient(client, "test:")
	if s == nil {
		t.Fatal("NewWithClient returned nil")
	}
	if !s.ownsClient {
		t.Error("ownsClient should default to true (backward compatible)")
	}
	// Close で client.Close まで呼ばれることを観測
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := client.Ping(ctx).Err(); err == nil {
		t.Error("expected client to be closed after default NewWithClient + Close")
	}
}

// 追加: errors.Is でも使えるよう Close 多重呼び出しが冪等であることの確認（v0.2.x からの不変条件）。
func TestRedisStore_Close_Idempotent(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})

	s := NewWithClient(client, "test:")
	_ = s.Close()
	if err := s.Close(); err != nil && !errors.Is(err, nil) {
		// 2 回目以降の Close は sync.Once により内部の closer は走らない。
		// 一度目で得た error をそのまま返すか nil を返すか、いずれにせよ panic しないこと。
		t.Logf("second Close returned: %v", err)
	}
}
