package sqlite

import (
	"path/filepath"
	"testing"

	"github.com/youyo/idproxy"
	"github.com/youyo/idproxy/store/storetest"
)

func TestStore_Conformance(t *testing.T) {
	storetest.RunConformance(t, func(t *testing.T) (idproxy.Store, func()) {
		// 一時ファイル DB を使う（:memory: は MaxOpenConns=1 でテスト並列化に弱い）
		dbPath := filepath.Join(t.TempDir(), "store.db")
		s, err := NewWithCleanupInterval(dbPath, 0)
		if err != nil {
			t.Fatalf("NewWithCleanupInterval: %v", err)
		}
		return s, func() { _ = s.Close() }
	})
}
