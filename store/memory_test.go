package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/youyo/idproxy"
)

func testSession() *idproxy.Session {
	now := time.Now()
	return &idproxy.Session{
		ID:             "sess-001",
		User:           &idproxy.User{Email: "test@example.com", Name: "Test User", Subject: "sub-001", Issuer: "https://issuer.example.com"},
		ProviderIssuer: "https://issuer.example.com",
		IDToken:        "eyJhbGciOiJSUzI1NiJ9.test",
		CreatedAt:      now,
		ExpiresAt:      now.Add(24 * time.Hour),
	}
}

func TestNewMemoryStore(t *testing.T) {
	ms := NewMemoryStore()
	if ms == nil {
		t.Fatal("NewMemoryStore() returned nil")
	}

	// Store インターフェースを実装していることをコンパイル時に確認
	var _ idproxy.Store = ms
}

func TestMemoryStore_SetGetSession(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	sess := testSession()

	if err := ms.SetSession(ctx, sess.ID, sess, time.Hour); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}

	got, err := ms.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetSession() returned nil")
	}
	if got.ID != sess.ID {
		t.Errorf("ID = %q, want %q", got.ID, sess.ID)
	}
	if got.User == nil || got.User.Email != sess.User.Email {
		t.Errorf("User.Email = %v, want %v", got.User, sess.User)
	}
	if got.ProviderIssuer != sess.ProviderIssuer {
		t.Errorf("ProviderIssuer = %q, want %q", got.ProviderIssuer, sess.ProviderIssuer)
	}
	if got.IDToken != sess.IDToken {
		t.Errorf("IDToken = %q, want %q", got.IDToken, sess.IDToken)
	}
}

func TestMemoryStore_GetSession_NotFound(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()

	got, err := ms.GetSession(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetSession() = %v, want nil", got)
	}
}

func TestMemoryStore_GetSession_Expired(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	sess := testSession()

	// TTL を 0 に設定 → 即座に期限切れ
	if err := ms.SetSession(ctx, sess.ID, sess, 0); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}

	got, err := ms.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetSession() = %v, want nil (expired)", got)
	}
}

func TestMemoryStore_SetSession_Overwrite(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()

	sess1 := testSession()
	sess2 := testSession()
	sess2.IDToken = "updated-token"

	if err := ms.SetSession(ctx, sess1.ID, sess1, time.Hour); err != nil {
		t.Fatalf("SetSession(1) error = %v", err)
	}
	if err := ms.SetSession(ctx, sess1.ID, sess2, time.Hour); err != nil {
		t.Fatalf("SetSession(2) error = %v", err)
	}

	got, err := ms.GetSession(ctx, sess1.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetSession() returned nil")
	}
	if got.IDToken != "updated-token" {
		t.Errorf("IDToken = %q, want %q", got.IDToken, "updated-token")
	}
}

func TestMemoryStore_DeleteSession(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	sess := testSession()

	if err := ms.SetSession(ctx, sess.ID, sess, time.Hour); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}
	if err := ms.DeleteSession(ctx, sess.ID); err != nil {
		t.Fatalf("DeleteSession() error = %v", err)
	}

	got, err := ms.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetSession() = %v, want nil (deleted)", got)
	}
}

func TestMemoryStore_DeleteSession_NotFound(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()

	if err := ms.DeleteSession(ctx, "nonexistent"); err != nil {
		t.Errorf("DeleteSession() error = %v, want nil", err)
	}
}

func TestMemoryStore_SetSession_ContextCanceled(t *testing.T) {
	ms := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sess := testSession()

	err := ms.SetSession(ctx, sess.ID, sess, time.Hour)
	if err != context.Canceled {
		t.Errorf("SetSession() error = %v, want %v", err, context.Canceled)
	}
}

func TestMemoryStore_GetSession_ContextCanceled(t *testing.T) {
	ms := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := ms.GetSession(ctx, "any")
	if err != context.Canceled {
		t.Errorf("GetSession() error = %v, want %v", err, context.Canceled)
	}
	if got != nil {
		t.Errorf("GetSession() = %v, want nil", got)
	}
}

func TestMemoryStore_DeleteSession_ContextCanceled(t *testing.T) {
	ms := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := ms.DeleteSession(ctx, "any")
	if err != context.Canceled {
		t.Errorf("DeleteSession() error = %v, want %v", err, context.Canceled)
	}
}

func TestMemoryStore_Concurrent(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()
	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	for i := range goroutines {
		id := "sess-" + string(rune('A'+i%26))
		sess := &idproxy.Session{
			ID:   id,
			User: &idproxy.User{Email: id + "@example.com"},
		}

		// Set
		go func() {
			defer wg.Done()
			_ = ms.SetSession(ctx, id, sess, time.Hour)
		}()

		// Get
		go func() {
			defer wg.Done()
			_, _ = ms.GetSession(ctx, id)
		}()

		// Delete
		go func() {
			defer wg.Done()
			_ = ms.DeleteSession(ctx, id)
		}()
	}

	wg.Wait()
}
