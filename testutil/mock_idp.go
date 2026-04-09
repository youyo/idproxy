package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// MockIdP はテスト用の OIDC Identity Provider サーバーを表す。
// httptest.Server を内包し、ES256 署名の ID Token を発行できる。
type MockIdP struct {
	// Server はテスト用 HTTP サーバー。URL を取得するのに使用する。
	Server     *httptest.Server
	privateKey *ecdsa.PrivateKey
	keyID      string
	codes      map[string]codeEntry
	mu         sync.Mutex
}

// codeEntry は Authorization Code に紐づくユーザー情報を保持する。
type codeEntry struct {
	subject  string
	email    string
	nonce    string
	clientID string
}

// NewMockIdP はテスト用 OIDC IdP サーバーを起動し、MockIdP を返す。
// t.Cleanup で Server.Close が自動呼び出しされるため、テスト終了時に明示的なクリーンアップは不要。
func NewMockIdP(t testing.TB) *MockIdP {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("MockIdP: failed to generate ECDSA key: %v", err)
	}

	// keyID を crypto/rand で生成
	kidBytes := make([]byte, 8)
	if _, err := rand.Read(kidBytes); err != nil {
		t.Fatalf("MockIdP: failed to generate key ID: %v", err)
	}
	keyID := hex.EncodeToString(kidBytes)

	m := &MockIdP{
		privateKey: privateKey,
		keyID:      keyID,
		codes:      make(map[string]codeEntry),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", m.handleDiscovery)
	mux.HandleFunc("/jwks", m.handleJWKS)
	mux.HandleFunc("/authorize", m.handleAuthorize)
	mux.HandleFunc("/token", m.handleToken)

	m.Server = httptest.NewServer(mux)
	t.Cleanup(m.Server.Close)

	return m
}

// Issuer は OIDC Discovery の issuer フィールドと一致する URL を返す。
func (m *MockIdP) Issuer() string {
	return m.Server.URL
}

// PublicKey は JWT 署名検証用の ECDSA 公開鍵を返す。
func (m *MockIdP) PublicKey() *ecdsa.PublicKey {
	return &m.privateKey.PublicKey
}

// PrivateKey は JWT 署名用の ECDSA 秘密鍵を返す。
// テストで idproxy が発行するアクセストークンを生成する際に使用する。
func (m *MockIdP) PrivateKey() *ecdsa.PrivateKey {
	return m.privateKey
}

// IssueAccessToken は idproxy が発行するアクセストークン（JWT）を生成する。
// テストで Bearer Token 検証を検証する際に使用する。
func (m *MockIdP) IssueAccessToken(issuer, audience, subject, email, name, jti string, expiresAt time.Time) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   subject,
		"aud":   jwt.ClaimStrings{audience},
		"email": email,
		"name":  name,
		"jti":   jti,
		"iat":   now.Unix(),
		"exp":   expiresAt.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = m.keyID

	return token.SignedString(m.privateKey)
}

// IssueCode は指定した subject/email/clientID/nonce に紐づく Authorization Code を直接生成する。
// テストで /authorize を経由せずにトークン取得フローを検証したい場合に使用する。
func (m *MockIdP) IssueCode(subject, email, clientID, nonce string) string {
	codeBytes := make([]byte, 16)
	if _, err := rand.Read(codeBytes); err != nil {
		panic("MockIdP.IssueCode: rand.Read failed: " + err.Error())
	}
	code := hex.EncodeToString(codeBytes)

	m.mu.Lock()
	m.codes[code] = codeEntry{
		subject:  subject,
		email:    email,
		nonce:    nonce,
		clientID: clientID,
	}
	m.mu.Unlock()

	return code
}

// handleDiscovery は OIDC Discovery Document を返す。
func (m *MockIdP) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	issuer := m.Issuer()
	doc := map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	}
	writeJSON(w, http.StatusOK, doc)
}

// handleJWKS は JSON Web Key Set を返す。
// P-256 座標は 32バイト固定長にゼロパディングして base64url エンコードする。
func (m *MockIdP) handleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := m.privateKey.PublicKey
	ecdhPub, err := pub.ECDH()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	pubBytes := ecdhPub.Bytes() // 0x04 || X (32bytes) || Y (32bytes)
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "EC",
				"kid": m.keyID,
				"crv": "P-256",
				"x":   base64.RawURLEncoding.EncodeToString(pubBytes[1:33]),
				"y":   base64.RawURLEncoding.EncodeToString(pubBytes[33:65]),
				"use": "sig",
				"alg": "ES256",
			},
		},
	}
	writeJSON(w, http.StatusOK, jwks)
}

// handleAuthorize は Authorization Code を発行し、redirect_uri にリダイレクトする。
// クエリパラメータ subject / email でデフォルトユーザー情報を上書きできる。
func (m *MockIdP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	nonce := q.Get("nonce")
	clientID := q.Get("client_id")

	// subject / email はデフォルト値を持ち、テストからの上書きも許容する
	subject := q.Get("subject")
	if subject == "" {
		subject = "test-user-id"
	}
	email := q.Get("email")
	if email == "" {
		email = "test@example.com"
	}

	code := m.IssueCode(subject, email, clientID, nonce)

	// redirect_uri にコールバックリダイレクト
	callbackURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	callbackParams := callbackURL.Query()
	callbackParams.Set("code", code)
	if state != "" {
		callbackParams.Set("state", state)
	}
	callbackURL.RawQuery = callbackParams.Encode()

	http.Redirect(w, r, callbackURL.String(), http.StatusFound)
}

// handleToken は Authorization Code を受け取り、ID Token を発行する。
func (m *MockIdP) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")

	m.mu.Lock()
	entry, ok := m.codes[code]
	if ok {
		delete(m.codes, code)
	}
	m.mu.Unlock()

	if !ok {
		http.Error(w, `{"error":"invalid_grant","error_description":"code not found"}`, http.StatusBadRequest)
		return
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   m.Issuer(),
		"sub":   entry.subject,
		"aud":   jwt.ClaimStrings{entry.clientID},
		"email": entry.email,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	if entry.nonce != "" {
		claims["nonce"] = entry.nonce
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = m.keyID

	idToken, err := token.SignedString(m.privateKey)
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	// opaque access token（テスト用途のため単純な random hex）
	accessTokenBytes := make([]byte, 16)
	_, _ = rand.Read(accessTokenBytes)
	accessToken := hex.EncodeToString(accessTokenBytes)

	resp := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"id_token":     idToken,
		"expires_in":   3600,
	}
	writeJSON(w, http.StatusOK, resp)
}


// writeJSON は JSON レスポンスを書き込むヘルパー。
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
