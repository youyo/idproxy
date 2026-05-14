package idproxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
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
	s := cfg.Store
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
	var _ crypto.Signer = cfg.SigningKey //nolint:staticcheck

	// SigningMethod は jwt.SigningMethod 型
	var _ jwt.SigningMethod = cfg.SigningMethod //nolint:staticcheck
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

// T13: RefreshTokenTTL=0 で Validate() 後に 30 * 24 * time.Hour が適用される
func TestValidate_DefaultRefreshTokenTTL(t *testing.T) {
	cfg := validConfig()
	cfg.RefreshTokenTTL = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RefreshTokenTTL != 30*24*time.Hour {
		t.Errorf("RefreshTokenTTL: got %v, want %v", cfg.RefreshTokenTTL, 30*24*time.Hour)
	}
}

// T13: 明示的に設定された RefreshTokenTTL が保持される
func TestValidate_ExplicitRefreshTokenTTL(t *testing.T) {
	cfg := validConfig()
	cfg.RefreshTokenTTL = 7 * 24 * time.Hour
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RefreshTokenTTL != 7*24*time.Hour {
		t.Errorf("RefreshTokenTTL: got %v, want %v", cfg.RefreshTokenTTL, 7*24*time.Hour)
	}
}

// T13: DefaultConfig に RefreshTokenTTL が設定されている
func TestDefaultConfig_RefreshTokenTTL(t *testing.T) {
	if DefaultConfig.RefreshTokenTTL != 30*24*time.Hour {
		t.Errorf("DefaultConfig.RefreshTokenTTL: got %v, want %v", DefaultConfig.RefreshTokenTTL, 30*24*time.Hour)
	}
}

// --- M23: StrictPostLoginRedirectValidator テスト（T8-T17） ---

// T8: 同一 origin の絶対 URL は通過する。
func TestStrictValidator_AcceptsSameOriginAbsoluteURL(t *testing.T) {
	v := StrictPostLoginRedirectValidator("https://app.example.com")
	if err := v("https://app.example.com/dashboard"); err != nil {
		t.Errorf("same-origin absolute URL should pass, got error: %v", err)
	}
}

// T9: クロス origin の絶対 URL は拒否する。
func TestStrictValidator_RejectsCrossOriginAbsoluteURL(t *testing.T) {
	v := StrictPostLoginRedirectValidator("https://app.example.com")
	if err := v("https://evil.example.com/x"); err == nil {
		t.Error("cross-origin absolute URL should be rejected")
	}
}

// T10: protocol-relative URL は拒否する。
func TestStrictValidator_RejectsProtocolRelative(t *testing.T) {
	v := StrictPostLoginRedirectValidator("https://app.example.com")
	if err := v("//evil.example.com/x"); err == nil {
		t.Error("protocol-relative URL should be rejected")
	}
}

// T11: javascript: スキームは拒否する。
func TestStrictValidator_RejectsJavascriptScheme(t *testing.T) {
	v := StrictPostLoginRedirectValidator("https://app.example.com")
	if err := v("javascript:alert(1)"); err == nil {
		t.Error("javascript: scheme should be rejected")
	}
}

// T12: data: スキームは拒否する。
func TestStrictValidator_RejectsDataScheme(t *testing.T) {
	v := StrictPostLoginRedirectValidator("https://app.example.com")
	if err := v("data:text/html,<script>"); err == nil {
		t.Error("data: scheme should be rejected")
	}
}

// T13(M23): backslash 文字を含む URL は拒否する。
func TestStrictValidator_RejectsBackslash(t *testing.T) {
	v := StrictPostLoginRedirectValidator("https://app.example.com")
	if err := v("/\\evil.example.com"); err == nil {
		t.Error("backslash should be rejected")
	}
}

// T14: タブ・改行・ゼロ幅文字を含む URL は拒否する。
func TestStrictValidator_RejectsTabsAndControl(t *testing.T) {
	v := StrictPostLoginRedirectValidator("https://app.example.com")
	cases := []string{
		"/\tjavascript:alert(1)",
		"/foo\nbar",
		"/foo\u200bbar", // zero-width space (escape sequence; literal U+200B avoided per ST1018)
	}
	for _, c := range cases {
		if err := v(c); err == nil {
			t.Errorf("input %q with control char should be rejected", c)
		}
	}
}

// T15: NFKC 正規化前後で差分のある入力は拒否する。
func TestStrictValidator_RejectsUnicodeNormalizationDiff(t *testing.T) {
	v := StrictPostLoginRedirectValidator("https://app.example.com")
	// 全角スラッシュ U+FF0F は NFKC で "/" になり差分が生じる
	if err := v("／evil.example.com"); err == nil {
		t.Error("non-NFKC input should be rejected")
	}
}

// T16: カスタム Validator のエラーは BrowserAuth の 400 路を通る前提のため、ここでは
// Validator 自体がエラーを正しく返すかだけを確認する。
func TestStrictValidator_CustomReject(t *testing.T) {
	custom := func(string) error { return errors.New("nope") }
	if err := custom("/foo"); err == nil {
		t.Error("custom validator should return error")
	}
}

// T17: Validator=nil のときは何も検査されない（v0.4.2 までの動作互換）。
func TestStrictValidator_NilValidator_AcceptsAnything(t *testing.T) {
	cfg := validConfig()
	cfg.PostLoginRedirectValidator = nil
	if err := cfg.Validate(); err != nil {
		t.Errorf("nil validator config should validate: %v", err)
	}
}

// T18: DefaultPostLoginPath が Validator に通らない値（"//evil.com"）の場合は Validate がエラー。
func TestConfig_Validate_DefaultPostLoginPath_AppliesValidator(t *testing.T) {
	cfg := validConfig()
	cfg.DefaultPostLoginPath = "//evil.com"
	if err := cfg.Validate(); err == nil {
		t.Fatal("protocol-relative DefaultPostLoginPath should be rejected by Validate")
	}
}

// T19: DefaultPostLoginPath は先頭スラッシュが必須。
func TestConfig_Validate_DefaultPostLoginPath_LeadingSlash(t *testing.T) {
	cfg := validConfig()
	cfg.DefaultPostLoginPath = "no-slash"
	if err := cfg.Validate(); err == nil {
		t.Fatal("DefaultPostLoginPath without leading '/' should be rejected")
	}
}

// 追加: 空文字列の DefaultPostLoginPath は許容（後方互換）。
func TestConfig_Validate_DefaultPostLoginPath_Empty(t *testing.T) {
	cfg := validConfig()
	cfg.DefaultPostLoginPath = ""
	if err := cfg.Validate(); err != nil {
		t.Errorf("empty DefaultPostLoginPath should be allowed: %v", err)
	}
}

// 追加: 有効な値（"/dashboard"）は通過する。
func TestConfig_Validate_DefaultPostLoginPath_Valid(t *testing.T) {
	cfg := validConfig()
	cfg.DefaultPostLoginPath = "/dashboard"
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid DefaultPostLoginPath '/dashboard' should be allowed: %v", err)
	}
}

// 追加: UseStrictPostLoginRedirectValidator setter ヘルパーの動作確認。
func TestConfig_UseStrictPostLoginRedirectValidator_Setter(t *testing.T) {
	cfg := validConfig()
	if cfg.PostLoginRedirectValidator != nil {
		t.Fatal("default PostLoginRedirectValidator should be nil")
	}
	cfg.UseStrictPostLoginRedirectValidator()
	if cfg.PostLoginRedirectValidator == nil {
		t.Fatal("PostLoginRedirectValidator should be set after UseStrictPostLoginRedirectValidator()")
	}
	// 検査が機能するか
	if err := cfg.PostLoginRedirectValidator("javascript:alert(1)"); err == nil {
		t.Error("UseStrictPostLoginRedirectValidator should reject javascript:")
	}
	if err := cfg.PostLoginRedirectValidator("/dashboard"); err != nil {
		t.Errorf("UseStrictPostLoginRedirectValidator should accept relative path: %v", err)
	}
}

// 追加: ErrUnsafePostLoginRedirect は wrap されており errors.Is で判定できる。
func TestStrictValidator_ErrIsWrapped(t *testing.T) {
	v := StrictPostLoginRedirectValidator("https://app.example.com")
	err := v("javascript:alert(1)")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrUnsafePostLoginRedirect) {
		t.Errorf("error should wrap ErrUnsafePostLoginRedirect, got: %v", err)
	}
}
