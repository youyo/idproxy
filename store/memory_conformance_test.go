package store

import (
	"testing"

	"github.com/youyo/idproxy"
	"github.com/youyo/idproxy/store/storetest"
)

// TestMemoryStore_Conformance は MemoryStore が共通スイートを満たすことを検証する。
func TestMemoryStore_Conformance(t *testing.T) {
	storetest.RunConformance(t, func(t *testing.T) (idproxy.Store, func()) {
		s := newMemoryStoreWithInterval(0) // テスト中は cleanup goroutine 不要
		return s, func() { _ = s.Close() }
	})
}
