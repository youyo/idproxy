package redis

import (
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
