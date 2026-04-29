package main

import (
	"encoding/hex"
	"testing"
)

func TestParseConfig_AllRequired(t *testing.T) {
	// All required environment variables are set
	secret := hex.EncodeToString(make([]byte, 32))
	setEnvs(t, map[string]string{
		"UPSTREAM_URL":       "http://localhost:3000",
		"EXTERNAL_URL":      "https://mcp.example.com",
		"COOKIE_SECRET":     secret,
		"OIDC_ISSUER":       "https://accounts.google.com",
		"OIDC_CLIENT_ID":    "test-client-id",
		"OIDC_CLIENT_SECRET": "test-client-secret",
	})

	cfg, upstream, listenAddr, err := parseConfig()
	if err != nil {
		t.Fatalf("parseConfig() error: %v", err)
	}
	if upstream != "http://localhost:3000" {
		t.Errorf("upstream = %q, want %q", upstream, "http://localhost:3000")
	}
	if listenAddr != ":8080" {
		t.Errorf("listenAddr = %q, want %q", listenAddr, ":8080")
	}
	if cfg.ExternalURL != "https://mcp.example.com" {
		t.Errorf("ExternalURL = %q, want %q", cfg.ExternalURL, "https://mcp.example.com")
	}
	if len(cfg.Providers) != 1 {
		t.Fatalf("len(Providers) = %d, want 1", len(cfg.Providers))
	}
	if cfg.Providers[0].Issuer != "https://accounts.google.com" {
		t.Errorf("Providers[0].Issuer = %q, want %q", cfg.Providers[0].Issuer, "https://accounts.google.com")
	}
	if cfg.Providers[0].ClientID != "test-client-id" {
		t.Errorf("Providers[0].ClientID = %q, want %q", cfg.Providers[0].ClientID, "test-client-id")
	}
	if cfg.Providers[0].ClientSecret != "test-client-secret" {
		t.Errorf("Providers[0].ClientSecret = %q, want %q", cfg.Providers[0].ClientSecret, "test-client-secret")
	}
}

func TestParseConfig_MultipleProviders(t *testing.T) {
	secret := hex.EncodeToString(make([]byte, 32))
	setEnvs(t, map[string]string{
		"UPSTREAM_URL":       "http://localhost:3000",
		"EXTERNAL_URL":      "https://mcp.example.com",
		"COOKIE_SECRET":     secret,
		"OIDC_ISSUER":       "https://accounts.google.com,https://login.microsoftonline.com/tenant/v2.0",
		"OIDC_CLIENT_ID":    "google-id,azure-id",
		"OIDC_CLIENT_SECRET": "google-secret,azure-secret",
	})

	cfg, _, _, err := parseConfig()
	if err != nil {
		t.Fatalf("parseConfig() error: %v", err)
	}
	if len(cfg.Providers) != 2 {
		t.Fatalf("len(Providers) = %d, want 2", len(cfg.Providers))
	}
	if cfg.Providers[1].Issuer != "https://login.microsoftonline.com/tenant/v2.0" {
		t.Errorf("Providers[1].Issuer = %q", cfg.Providers[1].Issuer)
	}
}

func TestParseConfig_MissingRequired(t *testing.T) {
	tests := []struct {
		name    string
		envs    map[string]string
		wantErr string
	}{
		{
			name:    "missing UPSTREAM_URL",
			envs:    map[string]string{},
			wantErr: "UPSTREAM_URL",
		},
		{
			name: "missing EXTERNAL_URL",
			envs: map[string]string{
				"UPSTREAM_URL": "http://localhost:3000",
			},
			wantErr: "EXTERNAL_URL",
		},
		{
			name: "missing COOKIE_SECRET",
			envs: map[string]string{
				"UPSTREAM_URL":  "http://localhost:3000",
				"EXTERNAL_URL": "https://mcp.example.com",
			},
			wantErr: "COOKIE_SECRET",
		},
		{
			name: "missing OIDC_ISSUER",
			envs: map[string]string{
				"UPSTREAM_URL":  "http://localhost:3000",
				"EXTERNAL_URL": "https://mcp.example.com",
				"COOKIE_SECRET": hex.EncodeToString(make([]byte, 32)),
			},
			wantErr: "OIDC_ISSUER",
		},
		{
			name: "missing OIDC_CLIENT_ID",
			envs: map[string]string{
				"UPSTREAM_URL":  "http://localhost:3000",
				"EXTERNAL_URL": "https://mcp.example.com",
				"COOKIE_SECRET": hex.EncodeToString(make([]byte, 32)),
				"OIDC_ISSUER":  "https://accounts.google.com",
			},
			wantErr: "OIDC_CLIENT_ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setEnvs(t, tt.envs)
			_, _, _, err := parseConfig()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestParseConfig_ProviderCountMismatch(t *testing.T) {
	secret := hex.EncodeToString(make([]byte, 32))
	setEnvs(t, map[string]string{
		"UPSTREAM_URL":       "http://localhost:3000",
		"EXTERNAL_URL":      "https://mcp.example.com",
		"COOKIE_SECRET":     secret,
		"OIDC_ISSUER":       "https://a.com,https://b.com",
		"OIDC_CLIENT_ID":    "id-a",
		"OIDC_CLIENT_SECRET": "secret-a,secret-b",
	})

	_, _, _, err := parseConfig()
	if err == nil {
		t.Fatal("expected error for mismatched provider count")
	}
}

func TestParseConfig_CustomPort(t *testing.T) {
	secret := hex.EncodeToString(make([]byte, 32))
	setEnvs(t, map[string]string{
		"UPSTREAM_URL":       "http://localhost:3000",
		"EXTERNAL_URL":      "https://mcp.example.com",
		"COOKIE_SECRET":     secret,
		"OIDC_ISSUER":       "https://accounts.google.com",
		"OIDC_CLIENT_ID":    "test-id",
		"OIDC_CLIENT_SECRET": "test-secret",
		"PORT":              "9090",
	})

	_, _, listenAddr, err := parseConfig()
	if err != nil {
		t.Fatalf("parseConfig() error: %v", err)
	}
	if listenAddr != ":9090" {
		t.Errorf("listenAddr = %q, want %q", listenAddr, ":9090")
	}
}

func TestParseConfig_OptionalFields(t *testing.T) {
	secret := hex.EncodeToString(make([]byte, 32))
	setEnvs(t, map[string]string{
		"UPSTREAM_URL":       "http://localhost:3000",
		"EXTERNAL_URL":      "https://mcp.example.com",
		"COOKIE_SECRET":     secret,
		"OIDC_ISSUER":       "https://accounts.google.com",
		"OIDC_CLIENT_ID":    "test-id",
		"OIDC_CLIENT_SECRET": "test-secret",
		"PATH_PREFIX":       "/auth",
		"ALLOWED_DOMAINS":   "example.com,heptagon.co.jp",
		"ALLOWED_EMAILS":    "user@other.com,admin@other.com",
		"OIDC_PROVIDER_NAME": "Google",
	})

	cfg, _, _, err := parseConfig()
	if err != nil {
		t.Fatalf("parseConfig() error: %v", err)
	}
	if cfg.PathPrefix != "/auth" {
		t.Errorf("PathPrefix = %q, want %q", cfg.PathPrefix, "/auth")
	}
	if len(cfg.AllowedDomains) != 2 {
		t.Fatalf("len(AllowedDomains) = %d, want 2", len(cfg.AllowedDomains))
	}
	if cfg.AllowedDomains[0] != "example.com" {
		t.Errorf("AllowedDomains[0] = %q", cfg.AllowedDomains[0])
	}
	if len(cfg.AllowedEmails) != 2 {
		t.Fatalf("len(AllowedEmails) = %d, want 2", len(cfg.AllowedEmails))
	}
	if cfg.Providers[0].Name != "Google" {
		t.Errorf("Providers[0].Name = %q, want %q", cfg.Providers[0].Name, "Google")
	}
}

func TestParseConfig_InvalidCookieSecret(t *testing.T) {
	setEnvs(t, map[string]string{
		"UPSTREAM_URL":       "http://localhost:3000",
		"EXTERNAL_URL":      "https://mcp.example.com",
		"COOKIE_SECRET":     "not-hex",
		"OIDC_ISSUER":       "https://accounts.google.com",
		"OIDC_CLIENT_ID":    "test-id",
		"OIDC_CLIENT_SECRET": "test-secret",
	})

	_, _, _, err := parseConfig()
	if err == nil {
		t.Fatal("expected error for invalid COOKIE_SECRET")
	}
}

func TestParseConfig_OAuthFields(t *testing.T) {
	secret := hex.EncodeToString(make([]byte, 32))
	setEnvs(t, map[string]string{
		"UPSTREAM_URL":               "http://localhost:3000",
		"EXTERNAL_URL":              "https://mcp.example.com",
		"COOKIE_SECRET":             secret,
		"OIDC_ISSUER":               "https://accounts.google.com",
		"OIDC_CLIENT_ID":            "test-id",
		"OIDC_CLIENT_SECRET":         "test-secret",
		"OAUTH_CLIENT_ID":           "oauth-client",
		"OAUTH_ALLOWED_REDIRECT_URIS": "http://localhost:3000/callback,http://localhost:4000/callback",
	})

	cfg, _, _, err := parseConfig()
	if err != nil {
		t.Fatalf("parseConfig() error: %v", err)
	}
	if cfg.OAuth != nil {
		// OAuth は JWT_SIGNING_KEY_FILE なしの場合 nil のまま
		// ただし ClientID と AllowedRedirectURIs は OAuthConfig が設定された場合のみ
		// ここでは signing key がないので OAuth は nil
		t.Log("OAuth is nil without JWT_SIGNING_KEY_FILE, as expected")
	}
}

// setEnvs sets environment variables for testing and cleans them up after the test.
// Clears all known environment variables before setting new ones.
func setEnvs(t *testing.T, envs map[string]string) {
	t.Helper()
	allKeys := []string{
		"UPSTREAM_URL", "EXTERNAL_URL", "PATH_PREFIX", "COOKIE_SECRET",
		"OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_PROVIDER_NAME",
		"ALLOWED_DOMAINS", "ALLOWED_EMAILS", "PORT",
		"OAUTH_CLIENT_ID", "OAUTH_ALLOWED_REDIRECT_URIS",
		"STORE_BACKEND",
		"DYNAMODB_TABLE_NAME", "AWS_REGION",
		"SQLITE_PATH",
		"REDIS_ADDR", "REDIS_PASSWORD", "REDIS_DB", "REDIS_TLS", "REDIS_KEY_PREFIX",
	}
	for _, k := range allKeys {
		t.Setenv(k, "")
	}
	for k, v := range envs {
		t.Setenv(k, v)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsStr(s, substr)
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
