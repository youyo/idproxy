// Package storetest は idproxy.Store 実装の適合性テストスイートを提供する。
//
// 使い方:
//
//	func TestMyStore(t *testing.T) {
//	    storetest.RunConformance(t, func(t *testing.T) (idproxy.Store, func()) {
//	        s := newMyStore()
//	        return s, func() { _ = s.Close() }
//	    })
//	}
package storetest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/youyo/idproxy"
)

// Factory は新しい Store と teardown 関数を返すファクトリ関数。
// 各サブテストごとに独立したインスタンスを返すことが望ましい。
type Factory func(t *testing.T) (idproxy.Store, func())

// RunConformance は idproxy.Store 実装が満たすべき動作を網羅的にテストする。
func RunConformance(t *testing.T, newStore Factory) {
	t.Helper()

	t.Run("Session", func(t *testing.T) { runSessionTests(t, newStore) })
	t.Run("AuthCode", func(t *testing.T) { runAuthCodeTests(t, newStore) })
	t.Run("AccessToken", func(t *testing.T) { runAccessTokenTests(t, newStore) })
	t.Run("Client", func(t *testing.T) { runClientTests(t, newStore) })
	t.Run("RefreshToken", func(t *testing.T) { runRefreshTokenTests(t, newStore) })
	t.Run("FamilyRevocation", func(t *testing.T) { runFamilyRevocationTests(t, newStore) })
	t.Run("Cleanup", func(t *testing.T) { runCleanupTests(t, newStore) })
	t.Run("Close", func(t *testing.T) { runCloseTests(t, newStore) })
	t.Run("ContextCanceled", func(t *testing.T) { runContextCanceledTests(t, newStore) })
}

// --- テストデータ生成ヘルパー（外部からも利用可能）---

func NewSession(id string) *idproxy.Session {
	now := time.Now()
	return &idproxy.Session{
		ID:             id,
		User:           &idproxy.User{Email: "test@example.com", Name: "Test User", Subject: "sub-001", Issuer: "https://issuer.example.com"},
		ProviderIssuer: "https://issuer.example.com",
		IDToken:        "eyJhbGciOiJSUzI1NiJ9.test",
		CreatedAt:      now,
		ExpiresAt:      now.Add(24 * time.Hour),
	}
}

func NewAuthCodeData(code string) *idproxy.AuthCodeData {
	now := time.Now()
	return &idproxy.AuthCodeData{
		Code:                code,
		ClientID:            "client-001",
		RedirectURI:         "https://app.example.com/callback",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		Scopes:              []string{"openid", "profile"},
		User:                &idproxy.User{Email: "test@example.com", Subject: "sub-001"},
		CreatedAt:           now,
		ExpiresAt:           now.Add(10 * time.Minute),
	}
}

func NewAccessTokenData(jti string) *idproxy.AccessTokenData {
	now := time.Now()
	return &idproxy.AccessTokenData{
		JTI:       jti,
		Subject:   "sub-001",
		Email:     "test@example.com",
		ClientID:  "client-001",
		Scopes:    []string{"openid", "profile"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}
}

func NewClientData(clientID string) *idproxy.ClientData {
	return &idproxy.ClientData{
		ClientID:                clientID,
		ClientName:              "Test Client",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   "openid profile",
		CreatedAt:               time.Now(),
	}
}

// NewRefreshTokenData は本番想定 (30 日 RT) のテストデータを返す。
// ExpiresAt は本番 oauth_server と同じく長期有効期限を設定するが、
// Store の TTL 契約は SetRefreshToken の `ttl` 引数側に従う点に注意。
// 各テストでは `ttl` を引数で別途指定するため、
// `ExpiresAt` と `ttl` が一致しないテストケースが存在しうる
// （例: ConsumeExpired は ttl=1ns を渡し ExpiresAt は 30 日）。
// 本番では oauth_server が両者を揃えるため、これは Store 実装が
// `ttl` 引数のみを TTL 判定に使うことを担保するための意図的な分離。
func NewRefreshTokenData(id string) *idproxy.RefreshTokenData {
	now := time.Now()
	return &idproxy.RefreshTokenData{
		ID:        id,
		FamilyID:  "family-uuid-001",
		ClientID:  "client-001",
		Subject:   "sub-001",
		Email:     "test@example.com",
		Name:      "Test User",
		Scopes:    []string{"openid", "profile"},
		IssuedAt:  now,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
	}
}

// --- Session ---

func runSessionTests(t *testing.T, newStore Factory) {
	t.Run("SetGet", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()
		sess := NewSession("sess-001")

		if err := s.SetSession(ctx, sess.ID, sess, time.Hour); err != nil {
			t.Fatalf("SetSession: %v", err)
		}
		got, err := s.GetSession(ctx, sess.ID)
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if got == nil {
			t.Fatal("GetSession returned nil")
		}
		if got.ID != sess.ID || got.User.Email != sess.User.Email || got.IDToken != sess.IDToken {
			t.Errorf("session mismatch: got %+v want %+v", got, sess)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		got, err := s.GetSession(context.Background(), "nonexistent")
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("Expired", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()
		sess := NewSession("sess-exp")
		if err := s.SetSession(ctx, sess.ID, sess, time.Nanosecond); err != nil {
			t.Fatalf("SetSession: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
		got, err := s.GetSession(ctx, sess.ID)
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil (expired), got %+v", got)
		}
	})

	t.Run("Overwrite", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()
		sess1 := NewSession("sess-ow")
		sess2 := NewSession("sess-ow")
		sess2.IDToken = "updated-token"

		if err := s.SetSession(ctx, sess1.ID, sess1, time.Hour); err != nil {
			t.Fatalf("SetSession 1: %v", err)
		}
		if err := s.SetSession(ctx, sess1.ID, sess2, time.Hour); err != nil {
			t.Fatalf("SetSession 2: %v", err)
		}

		got, err := s.GetSession(ctx, sess1.ID)
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if got == nil || got.IDToken != "updated-token" {
			t.Errorf("overwrite failed: %+v", got)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()
		sess := NewSession("sess-del")
		_ = s.SetSession(ctx, sess.ID, sess, time.Hour)
		if err := s.DeleteSession(ctx, sess.ID); err != nil {
			t.Fatalf("DeleteSession: %v", err)
		}
		got, _ := s.GetSession(ctx, sess.ID)
		if got != nil {
			t.Errorf("expected nil after delete, got %+v", got)
		}
	})

	t.Run("DeleteNotFound", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		if err := s.DeleteSession(context.Background(), "nonexistent"); err != nil {
			t.Errorf("DeleteSession should be idempotent, got: %v", err)
		}
	})
}

// --- AuthCode ---

func runAuthCodeTests(t *testing.T, newStore Factory) {
	t.Run("SetGet", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()
		data := NewAuthCodeData("code-abc")
		if err := s.SetAuthCode(ctx, data.Code, data, time.Hour); err != nil {
			t.Fatalf("SetAuthCode: %v", err)
		}
		got, err := s.GetAuthCode(ctx, data.Code)
		if err != nil {
			t.Fatalf("GetAuthCode: %v", err)
		}
		if got == nil || got.ClientID != data.ClientID || got.RedirectURI != data.RedirectURI {
			t.Errorf("authcode mismatch: %+v", got)
		}
		if len(got.Scopes) != 2 {
			t.Errorf("scopes mismatch: %v", got.Scopes)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		got, err := s.GetAuthCode(context.Background(), "nope")
		if err != nil {
			t.Fatalf("GetAuthCode: %v", err)
		}
		if got != nil {
			t.Error("expected nil")
		}
	})

	t.Run("Expired", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()
		data := NewAuthCodeData("code-exp")
		_ = s.SetAuthCode(ctx, data.Code, data, time.Nanosecond)
		time.Sleep(10 * time.Millisecond)
		got, _ := s.GetAuthCode(ctx, data.Code)
		if got != nil {
			t.Error("expected nil (expired)")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()
		data := NewAuthCodeData("code-del")
		_ = s.SetAuthCode(ctx, data.Code, data, time.Hour)
		if err := s.DeleteAuthCode(ctx, data.Code); err != nil {
			t.Fatalf("DeleteAuthCode: %v", err)
		}
		got, _ := s.GetAuthCode(ctx, data.Code)
		if got != nil {
			t.Error("expected nil after delete")
		}
	})

	t.Run("DeleteNotFound", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		if err := s.DeleteAuthCode(context.Background(), "nope"); err != nil {
			t.Errorf("DeleteAuthCode should be idempotent: %v", err)
		}
	})
}

// --- AccessToken ---

func runAccessTokenTests(t *testing.T, newStore Factory) {
	t.Run("SetGet", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()
		data := NewAccessTokenData("jti-001")
		if err := s.SetAccessToken(ctx, data.JTI, data, time.Hour); err != nil {
			t.Fatalf("SetAccessToken: %v", err)
		}
		got, err := s.GetAccessToken(ctx, data.JTI)
		if err != nil {
			t.Fatalf("GetAccessToken: %v", err)
		}
		if got == nil || got.Subject != data.Subject {
			t.Errorf("token mismatch: %+v", got)
		}
	})

	t.Run("Revoked", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()
		data := NewAccessTokenData("jti-rev")
		data.Revoked = true
		_ = s.SetAccessToken(ctx, data.JTI, data, time.Hour)
		got, _ := s.GetAccessToken(ctx, data.JTI)
		if got == nil || !got.Revoked {
			t.Errorf("expected revoked=true, got %+v", got)
		}
	})

	t.Run("Expired", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()
		data := NewAccessTokenData("jti-exp")
		_ = s.SetAccessToken(ctx, data.JTI, data, time.Nanosecond)
		time.Sleep(10 * time.Millisecond)
		got, _ := s.GetAccessToken(ctx, data.JTI)
		if got != nil {
			t.Error("expected nil (expired)")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()
		data := NewAccessTokenData("jti-del")
		_ = s.SetAccessToken(ctx, data.JTI, data, time.Hour)
		_ = s.DeleteAccessToken(ctx, data.JTI)
		got, _ := s.GetAccessToken(ctx, data.JTI)
		if got != nil {
			t.Error("expected nil after delete")
		}
	})
}

// --- Client ---

func runClientTests(t *testing.T, newStore Factory) {
	t.Run("SetGet", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()
		c := NewClientData("client-abc")
		if err := s.SetClient(ctx, c.ClientID, c); err != nil {
			t.Fatalf("SetClient: %v", err)
		}
		got, err := s.GetClient(ctx, c.ClientID)
		if err != nil {
			t.Fatalf("GetClient: %v", err)
		}
		if got == nil || got.ClientName != c.ClientName || len(got.RedirectURIs) != 1 {
			t.Errorf("client mismatch: %+v", got)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		got, err := s.GetClient(context.Background(), "nope")
		if err != nil {
			t.Fatalf("GetClient: %v", err)
		}
		if got != nil {
			t.Error("expected nil")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()
		c := NewClientData("client-del")
		_ = s.SetClient(ctx, c.ClientID, c)
		_ = s.DeleteClient(ctx, c.ClientID)
		got, _ := s.GetClient(ctx, c.ClientID)
		if got != nil {
			t.Error("expected nil after delete")
		}
	})
}

// --- RefreshToken ---

func runRefreshTokenTests(t *testing.T, newStore Factory) {
	t.Run("SetGet", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()
		data := NewRefreshTokenData("rt-001")
		if err := s.SetRefreshToken(ctx, data.ID, data, time.Hour); err != nil {
			t.Fatalf("SetRefreshToken: %v", err)
		}
		got, err := s.GetRefreshToken(ctx, data.ID)
		if err != nil {
			t.Fatalf("GetRefreshToken: %v", err)
		}
		if got == nil || got.FamilyID != data.FamilyID || got.Used {
			t.Errorf("rt mismatch: %+v", got)
		}
	})

	t.Run("ConsumeFirst", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()
		data := NewRefreshTokenData("rt-c1")
		_ = s.SetRefreshToken(ctx, data.ID, data, time.Hour)

		got, err := s.ConsumeRefreshToken(ctx, data.ID)
		if err != nil {
			t.Fatalf("ConsumeRefreshToken: %v", err)
		}
		if got == nil || !got.Used {
			t.Errorf("expected Used=true, got %+v", got)
		}
		// 永続化された値も Used=true
		stored, _ := s.GetRefreshToken(ctx, data.ID)
		if stored == nil || !stored.Used {
			t.Errorf("stored Used should be true: %+v", stored)
		}
	})

	t.Run("ConsumeReplay", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()
		data := NewRefreshTokenData("rt-replay")
		_ = s.SetRefreshToken(ctx, data.ID, data, time.Hour)

		_, err := s.ConsumeRefreshToken(ctx, data.ID)
		if err != nil {
			t.Fatalf("first consume: %v", err)
		}
		got, err := s.ConsumeRefreshToken(ctx, data.ID)
		if err != idproxy.ErrRefreshTokenAlreadyConsumed {
			t.Fatalf("second consume err = %v, want ErrRefreshTokenAlreadyConsumed", err)
		}
		if got == nil || got.FamilyID != data.FamilyID {
			t.Errorf("replay should return data with FamilyID, got %+v", got)
		}
	})

	t.Run("ConsumeNotFound", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		got, err := s.ConsumeRefreshToken(context.Background(), "nope")
		if err != nil {
			t.Fatalf("ConsumeRefreshToken: %v", err)
		}
		if got != nil {
			t.Error("expected nil")
		}
	})

	t.Run("ConsumeExpired", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()
		data := NewRefreshTokenData("rt-exp")
		_ = s.SetRefreshToken(ctx, data.ID, data, time.Nanosecond)
		time.Sleep(10 * time.Millisecond)
		got, err := s.ConsumeRefreshToken(ctx, data.ID)
		if err != nil {
			t.Fatalf("ConsumeRefreshToken: %v", err)
		}
		if got != nil {
			t.Error("expected nil (expired)")
		}
	})

	t.Run("ConsumeRace", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()
		data := NewRefreshTokenData("rt-race")
		_ = s.SetRefreshToken(ctx, data.ID, data, time.Hour)

		const goroutines = 20
		results := make([]error, goroutines)
		datas := make([]*idproxy.RefreshTokenData, goroutines)
		var wg sync.WaitGroup
		wg.Add(goroutines)

		for i := range goroutines {
			idx := i
			go func() {
				defer wg.Done()
				d, err := s.ConsumeRefreshToken(ctx, data.ID)
				results[idx] = err
				datas[idx] = d
			}()
		}
		wg.Wait()

		successCount := 0
		for i, err := range results {
			if err == nil && datas[i] != nil {
				successCount++
			} else if err == idproxy.ErrRefreshTokenAlreadyConsumed {
				if datas[i] == nil || datas[i].FamilyID != data.FamilyID {
					t.Errorf("goroutine %d: replay must return data with FamilyID", i)
				}
			}
		}
		if successCount != 1 {
			t.Errorf("successCount = %d, want exactly 1", successCount)
		}
	})
}

// --- FamilyRevocation ---

func runFamilyRevocationTests(t *testing.T, newStore Factory) {
	t.Run("SetCheck", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()
		if err := s.SetFamilyRevocation(ctx, "fam-1", time.Hour); err != nil {
			t.Fatalf("SetFamilyRevocation: %v", err)
		}
		ok, err := s.IsFamilyRevoked(ctx, "fam-1")
		if err != nil {
			t.Fatalf("IsFamilyRevoked: %v", err)
		}
		if !ok {
			t.Error("expected revoked=true")
		}
	})

	t.Run("NotSet", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ok, err := s.IsFamilyRevoked(context.Background(), "fam-unknown")
		if err != nil {
			t.Fatalf("IsFamilyRevoked: %v", err)
		}
		if ok {
			t.Error("expected revoked=false")
		}
	})

	t.Run("Expired", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()
		_ = s.SetFamilyRevocation(ctx, "fam-exp", time.Nanosecond)
		time.Sleep(10 * time.Millisecond)
		ok, _ := s.IsFamilyRevoked(ctx, "fam-exp")
		if ok {
			t.Error("expected revoked=false (expired)")
		}
	})
}

// --- Cleanup ---

func runCleanupTests(t *testing.T, newStore Factory) {
	t.Run("RemovesExpired", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx := context.Background()

		_ = s.SetSession(ctx, "s-exp", NewSession("s-exp"), time.Nanosecond)
		_ = s.SetSession(ctx, "s-ok", NewSession("s-ok"), time.Hour)
		_ = s.SetAuthCode(ctx, "a-exp", NewAuthCodeData("a-exp"), time.Nanosecond)
		_ = s.SetAuthCode(ctx, "a-ok", NewAuthCodeData("a-ok"), time.Hour)
		_ = s.SetAccessToken(ctx, "t-exp", NewAccessTokenData("t-exp"), time.Nanosecond)
		_ = s.SetAccessToken(ctx, "t-ok", NewAccessTokenData("t-ok"), time.Hour)
		_ = s.SetRefreshToken(ctx, "r-exp", NewRefreshTokenData("r-exp"), time.Nanosecond)
		_ = s.SetRefreshToken(ctx, "r-ok", NewRefreshTokenData("r-ok"), time.Hour)
		_ = s.SetFamilyRevocation(ctx, "f-exp", time.Nanosecond)
		_ = s.SetFamilyRevocation(ctx, "f-ok", time.Hour)
		time.Sleep(10 * time.Millisecond)

		if err := s.Cleanup(ctx); err != nil {
			t.Fatalf("Cleanup: %v", err)
		}

		// 期限切れは GET で nil
		if got, _ := s.GetSession(ctx, "s-exp"); got != nil {
			t.Error("s-exp should be gone")
		}
		if got, _ := s.GetSession(ctx, "s-ok"); got == nil {
			t.Error("s-ok should remain")
		}
		if got, _ := s.GetAuthCode(ctx, "a-exp"); got != nil {
			t.Error("a-exp should be gone")
		}
		if got, _ := s.GetAuthCode(ctx, "a-ok"); got == nil {
			t.Error("a-ok should remain")
		}
		if got, _ := s.GetAccessToken(ctx, "t-exp"); got != nil {
			t.Error("t-exp should be gone")
		}
		if got, _ := s.GetAccessToken(ctx, "t-ok"); got == nil {
			t.Error("t-ok should remain")
		}
		if got, _ := s.GetRefreshToken(ctx, "r-exp"); got != nil {
			t.Error("r-exp should be gone")
		}
		if got, _ := s.GetRefreshToken(ctx, "r-ok"); got == nil {
			t.Error("r-ok should remain")
		}
		if ok, _ := s.IsFamilyRevoked(ctx, "f-exp"); ok {
			t.Error("f-exp should be gone")
		}
		if ok, _ := s.IsFamilyRevoked(ctx, "f-ok"); !ok {
			t.Error("f-ok should remain")
		}
	})
}

// --- Close ---

func runCloseTests(t *testing.T, newStore Factory) {
	t.Run("Idempotent", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		if err := s.Close(); err != nil {
			t.Errorf("first Close: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Errorf("second Close: %v", err)
		}
	})
}

// --- ContextCanceled ---

func runContextCanceledTests(t *testing.T, newStore Factory) {
	t.Run("AllOps", func(t *testing.T) {
		s, cleanup := newStore(t)
		defer cleanup()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		ops := []struct {
			name string
			fn   func() error
		}{
			{"SetSession", func() error { return s.SetSession(ctx, "x", NewSession("x"), time.Hour) }},
			{"GetSession", func() error { _, err := s.GetSession(ctx, "x"); return err }},
			{"DeleteSession", func() error { return s.DeleteSession(ctx, "x") }},
			{"SetAuthCode", func() error { return s.SetAuthCode(ctx, "x", NewAuthCodeData("x"), time.Hour) }},
			{"GetAuthCode", func() error { _, err := s.GetAuthCode(ctx, "x"); return err }},
			{"DeleteAuthCode", func() error { return s.DeleteAuthCode(ctx, "x") }},
			{"SetAccessToken", func() error { return s.SetAccessToken(ctx, "x", NewAccessTokenData("x"), time.Hour) }},
			{"GetAccessToken", func() error { _, err := s.GetAccessToken(ctx, "x"); return err }},
			{"DeleteAccessToken", func() error { return s.DeleteAccessToken(ctx, "x") }},
			{"SetClient", func() error { return s.SetClient(ctx, "x", NewClientData("x")) }},
			{"GetClient", func() error { _, err := s.GetClient(ctx, "x"); return err }},
			{"SetRefreshToken", func() error { return s.SetRefreshToken(ctx, "x", NewRefreshTokenData("x"), time.Hour) }},
			{"GetRefreshToken", func() error { _, err := s.GetRefreshToken(ctx, "x"); return err }},
			{"ConsumeRefreshToken", func() error { _, err := s.ConsumeRefreshToken(ctx, "x"); return err }},
			{"SetFamilyRevocation", func() error { return s.SetFamilyRevocation(ctx, "x", time.Hour) }},
			{"IsFamilyRevoked", func() error { _, err := s.IsFamilyRevoked(ctx, "x"); return err }},
			{"Cleanup", func() error { return s.Cleanup(ctx) }},
		}
		for _, op := range ops {
			if err := op.fn(); err != context.Canceled {
				t.Errorf("%s: err = %v, want context.Canceled", op.name, err)
			}
		}
	})
}
