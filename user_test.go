package idproxy

import (
	"context"
	"testing"
)

func TestUserStructFields(t *testing.T) {
	u := User{
		Email:   "user@example.com",
		Name:    "Test User",
		Subject: "sub-123",
		Issuer:  "https://accounts.google.com",
		Claims: map[string]interface{}{
			"email":          "user@example.com",
			"email_verified": true,
		},
	}

	if u.Email != "user@example.com" {
		t.Errorf("Email: got %q", u.Email)
	}
	if u.Name != "Test User" {
		t.Errorf("Name: got %q", u.Name)
	}
	if u.Subject != "sub-123" {
		t.Errorf("Subject: got %q", u.Subject)
	}
	if u.Issuer != "https://accounts.google.com" {
		t.Errorf("Issuer: got %q", u.Issuer)
	}
	if len(u.Claims) != 2 {
		t.Errorf("Claims: got %d items, want 2", len(u.Claims))
	}
}

func TestUserFromContext_WithUser(t *testing.T) {
	u := &User{
		Email:   "user@example.com",
		Name:    "Test User",
		Subject: "sub-123",
		Issuer:  "https://accounts.google.com",
	}

	ctx := newContextWithUser(context.Background(), u)
	got := UserFromContext(ctx)

	if got == nil {
		t.Fatal("UserFromContext returned nil, want non-nil")
	}
	if got.Email != u.Email {
		t.Errorf("Email: got %q, want %q", got.Email, u.Email)
	}
	if got.Subject != u.Subject {
		t.Errorf("Subject: got %q, want %q", got.Subject, u.Subject)
	}
}

func TestUserFromContext_WithoutUser(t *testing.T) {
	ctx := context.Background()
	got := UserFromContext(ctx)

	if got != nil {
		t.Errorf("UserFromContext returned %v, want nil", got)
	}
}

func TestUser_IDToken_DefaultEmpty(t *testing.T) {
	// IDToken フィールドを省略した場合、空文字列（後方互換）。
	u := User{
		Email:   "user@example.com",
		Subject: "sub-123",
	}
	if u.IDToken != "" {
		t.Errorf("IDToken: got %q, want empty (backward compat)", u.IDToken)
	}
}

func TestUser_IDToken_SetAndGet(t *testing.T) {
	rawToken := "eyJhbGciOiJSUzI1NiJ9.example"
	u := User{
		Email:   "user@example.com",
		Subject: "sub-123",
		IDToken: rawToken,
	}
	ctx := newContextWithUser(context.Background(), &u)
	got := UserFromContext(ctx)
	if got == nil {
		t.Fatal("UserFromContext returned nil")
	}
	if got.IDToken != rawToken {
		t.Errorf("IDToken: got %q, want %q", got.IDToken, rawToken)
	}
}
