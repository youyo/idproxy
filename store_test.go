package idproxy

import (
	"context"
	"testing"
	"time"
)

// mockStore は Store インターフェースのテスト用モック実装。
type mockStore struct{}

// コンパイル時に Store インターフェースの実装を検証する。
var _ Store = (*mockStore)(nil)

func (m *mockStore) SetSession(_ context.Context, _ string, _ *Session, _ time.Duration) error {
	return nil
}

func (m *mockStore) GetSession(_ context.Context, _ string) (*Session, error) {
	return nil, nil
}

func (m *mockStore) DeleteSession(_ context.Context, _ string) error {
	return nil
}

func (m *mockStore) SetAuthCode(_ context.Context, _ string, _ *AuthCodeData, _ time.Duration) error {
	return nil
}

func (m *mockStore) GetAuthCode(_ context.Context, _ string) (*AuthCodeData, error) {
	return nil, nil
}

func (m *mockStore) DeleteAuthCode(_ context.Context, _ string) error {
	return nil
}

func (m *mockStore) SetAccessToken(_ context.Context, _ string, _ *AccessTokenData, _ time.Duration) error {
	return nil
}

func (m *mockStore) GetAccessToken(_ context.Context, _ string) (*AccessTokenData, error) {
	return nil, nil
}

func (m *mockStore) DeleteAccessToken(_ context.Context, _ string) error {
	return nil
}

func (m *mockStore) SetClient(_ context.Context, _ string, _ *ClientData) error {
	return nil
}

func (m *mockStore) GetClient(_ context.Context, _ string) (*ClientData, error) {
	return nil, nil
}

func (m *mockStore) DeleteClient(_ context.Context, _ string) error {
	return nil
}

func (m *mockStore) Cleanup(_ context.Context) error {
	return nil
}

func (m *mockStore) Close() error {
	return nil
}

func TestMockStoreImplementsStore(t *testing.T) {
	var _ Store = &mockStore{}
}

func TestSessionStructFields(t *testing.T) {
	now := time.Now()
	u := &User{Email: "user@example.com"}
	s := Session{
		ID:             "session-id",
		User:           u,
		ProviderIssuer: "https://accounts.google.com",
		IDToken:        "eyJhbGciOiJSUzI1NiJ9...",
		CreatedAt:      now,
		ExpiresAt:      now.Add(24 * time.Hour),
	}

	if s.ID != "session-id" {
		t.Errorf("ID: got %q", s.ID)
	}
	if s.User.Email != "user@example.com" {
		t.Errorf("User.Email: got %q", s.User.Email)
	}
	if s.ProviderIssuer != "https://accounts.google.com" {
		t.Errorf("ProviderIssuer: got %q", s.ProviderIssuer)
	}
	if s.IDToken == "" {
		t.Error("IDToken: got empty string")
	}
	if s.CreatedAt.IsZero() {
		t.Error("CreatedAt: got zero time")
	}
	if s.ExpiresAt.Before(s.CreatedAt) {
		t.Error("ExpiresAt should be after CreatedAt")
	}
}

func TestAuthCodeDataStructFields(t *testing.T) {
	now := time.Now()
	u := &User{Email: "user@example.com"}
	a := AuthCodeData{
		Code:                "auth-code-hex-32",
		ClientID:            "client-123",
		RedirectURI:         "https://app.example.com/callback",
		CodeChallenge:       "challenge-base64url",
		CodeChallengeMethod: "S256",
		Scopes:              []string{"openid", "email"},
		User:                u,
		CreatedAt:           now,
		ExpiresAt:           now.Add(10 * time.Minute),
		Used:                false,
	}

	if a.Code != "auth-code-hex-32" {
		t.Errorf("Code: got %q", a.Code)
	}
	if a.ClientID != "client-123" {
		t.Errorf("ClientID: got %q", a.ClientID)
	}
	if a.RedirectURI != "https://app.example.com/callback" {
		t.Errorf("RedirectURI: got %q", a.RedirectURI)
	}
	if a.CodeChallengeMethod != "S256" {
		t.Errorf("CodeChallengeMethod: got %q", a.CodeChallengeMethod)
	}
	if len(a.Scopes) != 2 {
		t.Errorf("Scopes: got %d, want 2", len(a.Scopes))
	}
	if a.User.Email != "user@example.com" {
		t.Errorf("User.Email: got %q", a.User.Email)
	}
	if a.Used {
		t.Error("Used: got true, want false")
	}
}

func TestAccessTokenDataStructFields(t *testing.T) {
	now := time.Now()
	a := AccessTokenData{
		JTI:       "jti-uuid",
		Subject:   "sub-123",
		Email:     "user@example.com",
		ClientID:  "client-123",
		Scopes:    []string{"openid"},
		IssuedAt:  now,
		ExpiresAt: now.Add(1 * time.Hour),
		Revoked:   false,
	}

	if a.JTI != "jti-uuid" {
		t.Errorf("JTI: got %q", a.JTI)
	}
	if a.Subject != "sub-123" {
		t.Errorf("Subject: got %q", a.Subject)
	}
	if a.Email != "user@example.com" {
		t.Errorf("Email: got %q", a.Email)
	}
	if a.ClientID != "client-123" {
		t.Errorf("ClientID: got %q", a.ClientID)
	}
	if len(a.Scopes) != 1 {
		t.Errorf("Scopes: got %d, want 1", len(a.Scopes))
	}
	if a.Revoked {
		t.Error("Revoked: got true, want false")
	}
}
