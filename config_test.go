package idproxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"strings"
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

// --- M03: Config バリデーション テスト ---

// validConfig はテスト用の最小限有効な Config を返す。
func validConfig() Config {
	return Config{
		Providers: []OIDCProvider{{
			Issuer:       "https://accounts.google.com",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		}},
		ExternalURL:  "https://auth.example.com",
		CookieSecret: make([]byte, 32),
	}
}

func TestValidate_MinimalValid(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_WithOAuth(t *testing.T) {
	cfg := validConfig()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	cfg.OAuth = &OAuthConfig{SigningKey: key}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_NoProviders(t *testing.T) {
	cfg := validConfig()
	cfg.Providers = nil
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "at least one provider") {
		t.Errorf("error should mention providers: %v", err)
	}
}

func TestValidate_ExternalURL_NotHTTPS(t *testing.T) {
	cfg := validConfig()
	cfg.ExternalURL = "http://example.com"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "external_url") {
		t.Errorf("error should mention external_url: %v", err)
	}
}

func TestValidate_ExternalURL_Localhost(t *testing.T) {
	cfg := validConfig()
	cfg.ExternalURL = "http://localhost:8080"
	if err := cfg.Validate(); err != nil {
		t.Errorf("localhost should be allowed: %v", err)
	}
}

func TestValidate_CookieSecret_TooShort(t *testing.T) {
	cfg := validConfig()
	cfg.CookieSecret = make([]byte, 31)
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "cookie_secret") {
		t.Errorf("error should mention cookie_secret: %v", err)
	}
}

func TestValidate_CookieSecret_Empty(t *testing.T) {
	cfg := validConfig()
	cfg.CookieSecret = nil
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "cookie_secret") {
		t.Errorf("error should mention cookie_secret: %v", err)
	}
}

func TestValidate_OAuth_NoSigningKey(t *testing.T) {
	cfg := validConfig()
	cfg.OAuth = &OAuthConfig{}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "signing_key") {
		t.Errorf("error should mention signing_key: %v", err)
	}
}

func TestValidate_Provider_EmptyIssuer(t *testing.T) {
	cfg := validConfig()
	cfg.Providers[0].Issuer = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Errorf("error should mention issuer: %v", err)
	}
}

func TestValidate_Provider_EmptyClientID(t *testing.T) {
	cfg := validConfig()
	cfg.Providers[0].ClientID = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "client_id") {
		t.Errorf("error should mention client_id: %v", err)
	}
}

func TestValidate_Provider_EmptyClientSecret(t *testing.T) {
	cfg := validConfig()
	cfg.Providers[0].ClientSecret = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "client_secret") {
		t.Errorf("error should mention client_secret: %v", err)
	}
}

func TestValidate_DefaultSessionMaxAge(t *testing.T) {
	cfg := validConfig()
	cfg.SessionMaxAge = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SessionMaxAge != 24*time.Hour {
		t.Errorf("SessionMaxAge: got %v, want %v", cfg.SessionMaxAge, 24*time.Hour)
	}
}

func TestValidate_DefaultAccessTokenTTL(t *testing.T) {
	cfg := validConfig()
	cfg.AccessTokenTTL = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AccessTokenTTL != 1*time.Hour {
		t.Errorf("AccessTokenTTL: got %v, want %v", cfg.AccessTokenTTL, 1*time.Hour)
	}
}

func TestValidate_DefaultAuthCodeTTL(t *testing.T) {
	cfg := validConfig()
	cfg.AuthCodeTTL = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AuthCodeTTL != 10*time.Minute {
		t.Errorf("AuthCodeTTL: got %v, want %v", cfg.AuthCodeTTL, 10*time.Minute)
	}
}

func TestValidate_DefaultScopes_Applied(t *testing.T) {
	cfg := validConfig()
	cfg.Providers[0].Scopes = nil
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []string{"openid", "email", "profile"}
	if len(cfg.Providers[0].Scopes) != len(expected) {
		t.Fatalf("Scopes: got %d, want %d", len(cfg.Providers[0].Scopes), len(expected))
	}
	for i, s := range cfg.Providers[0].Scopes {
		if s != expected[i] {
			t.Errorf("Scopes[%d]: got %q, want %q", i, s, expected[i])
		}
	}
	// DefaultScopes が変更されていないことを確認（スライスコピーの検証）
	if &cfg.Providers[0].Scopes[0] == &DefaultScopes[0] {
		t.Error("Scopes should be a copy, not a reference to DefaultScopes")
	}
}

func TestValidate_DefaultLogger(t *testing.T) {
	cfg := validConfig()
	cfg.Logger = nil
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Logger == nil {
		t.Error("Logger should be set to slog.Default()")
	}
}

func TestValidate_NoAllowedDomainsOrEmails(t *testing.T) {
	cfg := validConfig()
	cfg.AllowedDomains = nil
	cfg.AllowedEmails = nil
	if err := cfg.Validate(); err != nil {
		t.Errorf("should allow empty AllowedDomains/Emails: %v", err)
	}
}

func TestValidate_ExternalURL_127001(t *testing.T) {
	cfg := validConfig()
	cfg.ExternalURL = "http://127.0.0.1:8080"
	if err := cfg.Validate(); err != nil {
		t.Errorf("127.0.0.1 should be allowed: %v", err)
	}
}

func TestValidate_MultipleErrors(t *testing.T) {
	cfg := Config{} // Providers 空、ExternalURL 空、CookieSecret 空
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "provider") {
		t.Errorf("should mention provider: %v", err)
	}
	if !strings.Contains(errMsg, "cookie_secret") {
		t.Errorf("should mention cookie_secret: %v", err)
	}
}

func TestValidate_ExternalURL_Empty(t *testing.T) {
	cfg := validConfig()
	cfg.ExternalURL = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "external_url") {
		t.Errorf("error should mention external_url: %v", err)
	}
}
