package testutil_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/youyo/idproxy/testutil"
)

// TestMockIdP_Discovery は OIDC Discovery Document が正しく返されることを確認する。
func TestMockIdP_Discovery(t *testing.T) {
	m := testutil.NewMockIdP(t)

	resp, err := http.Get(m.Issuer() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("Discovery request failed: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("failed to decode discovery document: %v", err)
	}

	// issuer が MockIdP の URL と一致する
	if doc["issuer"] != m.Issuer() {
		t.Errorf("issuer mismatch: got %v, want %v", doc["issuer"], m.Issuer())
	}

	// 必須フィールドの存在確認
	requiredFields := []string{
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
		"response_types_supported",
		"id_token_signing_alg_values_supported",
	}
	for _, field := range requiredFields {
		if _, ok := doc[field]; !ok {
			t.Errorf("discovery document missing field: %s", field)
		}
	}

	// token_endpoint が正しい URL を指す
	tokenEP, ok := doc["token_endpoint"].(string)
	if !ok || tokenEP == "" {
		t.Errorf("token_endpoint is missing or empty")
	}
	if !strings.HasPrefix(tokenEP, m.Issuer()) {
		t.Errorf("token_endpoint should be under issuer URL: got %s", tokenEP)
	}
}

// TestMockIdP_JWKS は JWKS エンドポイントが ES256 鍵を含む JSON を返すことを確認する。
func TestMockIdP_JWKS(t *testing.T) {
	m := testutil.NewMockIdP(t)

	resp, err := http.Get(m.Issuer() + "/jwks")
	if err != nil {
		t.Fatalf("JWKS request failed: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("failed to decode JWKS: %v", err)
	}

	if len(jwks.Keys) == 0 {
		t.Fatal("JWKS keys array is empty")
	}

	key := jwks.Keys[0]
	if key["kty"] != "EC" {
		t.Errorf("expected kty=EC, got %v", key["kty"])
	}
	if key["crv"] != "P-256" {
		t.Errorf("expected crv=P-256, got %v", key["crv"])
	}
	if key["alg"] != "ES256" {
		t.Errorf("expected alg=ES256, got %v", key["alg"])
	}
	if key["kid"] == nil || key["kid"] == "" {
		t.Errorf("kid is missing or empty")
	}
	if key["x"] == nil || key["x"] == "" {
		t.Errorf("x coordinate is missing or empty")
	}
	if key["y"] == nil || key["y"] == "" {
		t.Errorf("y coordinate is missing or empty")
	}
}

// TestMockIdP_AuthFlow は Authorization Code フローの完全なフローを確認する。
func TestMockIdP_AuthFlow(t *testing.T) {
	m := testutil.NewMockIdP(t)

	// IssueCode を使って Authorization Code を直接取得
	code := m.IssueCode("user-123", "user@example.com", "my-client", "test-nonce")
	if code == "" {
		t.Fatal("IssueCode returned empty string")
	}

	// /token エンドポイントに POST
	tokenURL := m.Issuer() + "/token"
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"http://localhost/callback"},
		"client_id":    {"my-client"},
	}
	resp, err := http.PostForm(tokenURL, form)
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}

	idToken, ok := tokenResp["id_token"].(string)
	if !ok || idToken == "" {
		t.Fatal("id_token is missing or empty in token response")
	}

	// id_token の JWT 構造を確認（3パーツ）
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token does not look like a JWT: %s", idToken)
	}

	// access_token の存在確認
	if _, ok := tokenResp["access_token"]; !ok {
		t.Error("access_token missing in token response")
	}
}

// TestMockIdP_Authorize は /authorize エンドポイントがコールバックリダイレクトすることを確認する。
func TestMockIdP_Authorize(t *testing.T) {
	m := testutil.NewMockIdP(t)

	redirectURI := "http://localhost:9999/callback"
	authorizeURL := m.Issuer() + "/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {"test-client"},
		"redirect_uri":  {redirectURI},
		"state":         {"my-state-xyz"},
		"nonce":         {"my-nonce-abc"},
	}.Encode()

	// リダイレクトを追わないクライアントでリクエスト
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(authorizeURL)
	if err != nil {
		t.Fatalf("authorize request failed: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatal("Location header is missing")
	}

	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse Location: %v", err)
	}

	// state が保持されている
	if parsed.Query().Get("state") != "my-state-xyz" {
		t.Errorf("state mismatch in redirect: got %s", parsed.Query().Get("state"))
	}

	// code が含まれている
	code := parsed.Query().Get("code")
	if code == "" {
		t.Error("code is missing in redirect")
	}
}

// TestMockIdP_InvalidCode は存在しないコードでトークン要求すると 400 が返ることを確認する。
func TestMockIdP_InvalidCode(t *testing.T) {
	m := testutil.NewMockIdP(t)

	tokenURL := m.Issuer() + "/token"
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"invalid-code-does-not-exist"},
		"redirect_uri": {"http://localhost/callback"},
		"client_id":    {"some-client"},
	}
	resp, err := http.PostForm(tokenURL, form)
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid code, got %d", resp.StatusCode)
	}
}

// TestMockIdP_CodeOneTimeUse は Authorization Code が一回しか使えないことを確認する。
func TestMockIdP_CodeOneTimeUse(t *testing.T) {
	m := testutil.NewMockIdP(t)

	code := m.IssueCode("user-456", "user2@example.com", "client-x", "nonce-x")

	tokenURL := m.Issuer() + "/token"
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"http://localhost/callback"},
		"client_id":    {"client-x"},
	}

	// 1回目: 成功
	resp1, err := http.PostForm(tokenURL, form)
	if err != nil {
		t.Fatalf("first token request failed: %v", err)
	}
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first token request: expected 200, got %d", resp1.StatusCode)
	}

	// 2回目: コードは消費済みなので 400
	resp2, err := http.PostForm(tokenURL, form)
	if err != nil {
		t.Fatalf("second token request failed: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("second token request: expected 400 (code already used), got %d", resp2.StatusCode)
	}
}

// TestMockIdP_OIDCCompatibility は go-oidc ライブラリとの互換性を確認する。
// M10 で go-oidc が追加されるまでスキップ。
func TestMockIdP_OIDCCompatibility(t *testing.T) {
	t.Skip("go-oidc は M10 で追加予定。このテストは M10 でスキップ解除する。")
}
