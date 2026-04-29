package momento

import (
	"testing"
	"time"

	"github.com/youyo/idproxy"
	"github.com/youyo/idproxy/store/storetest"
)

func TestStore_Conformance(t *testing.T) {
	storetest.RunConformance(t, func(t *testing.T) (idproxy.Store, func()) {
		s := NewWithBackend(NewMemoryBackend(), "test:", time.Hour)
		return s, func() { _ = s.Close() }
	})
}
