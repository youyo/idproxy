package idproxy

import (
	"crypto"
	"log/slog"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestConfigStructFields(t *testing.T) {
	cfg := Config{
		Providers:      []OIDCProvider{{Issuer: "https://example.com"}},
		AllowedDomains: []string{"example.com"},
		AllowedEmails:  []string{"user@example.com"},
		ExternalURL:    "https://auth.example.com",
		CookieSecret:   []byte("secret-key-32-bytes-long-000000"),
		OAuth:          &OAuthConfig{},
		SessionMaxAge:  24 * time.Hour,
		AccessTokenTTL: 1 * time.Hour,
		AuthCodeTTL:    10 * time.Minute,
		Logger:         slog.Default(),
		PathPrefix:     "/auth",
	}

	if len(cfg.Providers) != 1 {
		t.Errorf("Providers: got %d, want 1", len(cfg.Providers))
	}
	if cfg.ExternalURL != "https://auth.example.com" {
		t.Errorf("ExternalURL: got %q, want %q", cfg.ExternalURL, "https://auth.example.com")
	}
	if cfg.SessionMaxAge != 24*time.Hour {
		t.Errorf("SessionMaxAge: got %v, want %v", cfg.SessionMaxAge, 24*time.Hour)
	}
	if cfg.AccessTokenTTL != 1*time.Hour {
		t.Errorf("AccessTokenTTL: got %v, want %v", cfg.AccessTokenTTL, 1*time.Hour)
	}
	if cfg.AuthCodeTTL != 10*time.Minute {
		t.Errorf("AuthCodeTTL: got %v, want %v", cfg.AuthCodeTTL, 10*time.Minute)
	}
	if cfg.PathPrefix != "/auth" {
		t.Errorf("PathPrefix: got %q, want %q", cfg.PathPrefix, "/auth")
	}

	// Store フィールドの型確認（nil 許容）
	var s Store = cfg.Store
	_ = s
}

func TestOIDCProviderStructFields(t *testing.T) {
	p := OIDCProvider{
		Issuer:       "https://accounts.google.com",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Scopes:       []string{"openid", "email"},
		Name:         "Google",
	}

	if p.Issuer != "https://accounts.google.com" {
		t.Errorf("Issuer: got %q", p.Issuer)
	}
	if p.ClientID != "client-id" {
		t.Errorf("ClientID: got %q", p.ClientID)
	}
	if p.ClientSecret != "client-secret" {
		t.Errorf("ClientSecret: got %q", p.ClientSecret)
	}
	if len(p.Scopes) != 2 {
		t.Errorf("Scopes: got %d, want 2", len(p.Scopes))
	}
	if p.Name != "Google" {
		t.Errorf("Name: got %q", p.Name)
	}
}

func TestOAuthConfigStructFields(t *testing.T) {
	cfg := OAuthConfig{}

	// SigningKey は crypto.Signer 型
	var _ crypto.Signer = cfg.SigningKey

	// SigningMethod は jwt.SigningMethod 型
	var _ jwt.SigningMethod = cfg.SigningMethod
}

func TestDefaultConfigValues(t *testing.T) {
	if DefaultConfig.SessionMaxAge != 24*time.Hour {
		t.Errorf("DefaultConfig.SessionMaxAge: got %v, want %v", DefaultConfig.SessionMaxAge, 24*time.Hour)
	}
	if DefaultConfig.AccessTokenTTL != 1*time.Hour {
		t.Errorf("DefaultConfig.AccessTokenTTL: got %v, want %v", DefaultConfig.AccessTokenTTL, 1*time.Hour)
	}
	if DefaultConfig.AuthCodeTTL != 10*time.Minute {
		t.Errorf("DefaultConfig.AuthCodeTTL: got %v, want %v", DefaultConfig.AuthCodeTTL, 10*time.Minute)
	}
	if DefaultConfig.PathPrefix != "" {
		t.Errorf("DefaultConfig.PathPrefix: got %q, want %q", DefaultConfig.PathPrefix, "")
	}
}

func TestDefaultScopes(t *testing.T) {
	expected := []string{"openid", "email", "profile"}
	if len(DefaultScopes) != len(expected) {
		t.Fatalf("DefaultScopes: got %d items, want %d", len(DefaultScopes), len(expected))
	}
	for i, s := range DefaultScopes {
		if s != expected[i] {
			t.Errorf("DefaultScopes[%d]: got %q, want %q", i, s, expected[i])
		}
	}
}
