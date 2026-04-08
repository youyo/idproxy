package idproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OAuthServer は OAuth 2.1 Authorization Server エンドポイントを提供する。
// RFC 8414 メタデータ、JWKS、および /authorize を処理する。
type OAuthServer struct {
	config Config
	store  Store
	// privateKey は Access Token 署名用 ES256 秘密鍵。
	privateKey *ecdsa.PrivateKey
	// keyID は JWKS の kid フィールドに使用する鍵識別子。
	keyID string
	// sessionManager はセッション管理（/authorize でユーザー認証確認に使用）。
	sessionManager *SessionManager
}

// NewOAuthServer は OAuthServer を構築する。
// Config.OAuth が設定されている場合はその SigningKey（ECDSA P-256）を使用する。
// Config.OAuth が nil の場合は ES256 鍵ペアを自動生成する。
// sm は SessionManager（/authorize でユーザー認証確認に使用）。nil の場合もエラーにはしない。
func NewOAuthServer(cfg Config, store Store, sm *SessionManager) (*OAuthServer, error) {
	var privateKey *ecdsa.PrivateKey

	if cfg.OAuth != nil && cfg.OAuth.SigningKey != nil {
		ecKey, ok := cfg.OAuth.SigningKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("oauth server requires ECDSA signing key")
		}
		if ecKey.Curve != elliptic.P256() {
			return nil, errors.New("oauth server requires ECDSA P-256 key (ES256)")
		}
		privateKey = ecKey
	} else {
		// 鍵ペアを自動生成
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		privateKey = key
	}

	// keyID を公開鍵の SHA-256 サムプリントから生成
	keyID := computeKeyID(&privateKey.PublicKey)

	return &OAuthServer{
		config:         cfg,
		store:          store,
		privateKey:     privateKey,
		keyID:          keyID,
		sessionManager: sm,
	}, nil
}

// ServeHTTP はリクエストを適切なハンドラーにルーティングする。
func (s *OAuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	prefix := s.config.PathPrefix

	switch r.URL.Path {
	case prefix + "/.well-known/oauth-authorization-server":
		s.metadataHandler(w, r)
	case prefix + "/.well-known/jwks.json":
		s.jwksHandler(w, r)
	case prefix + "/authorize":
		s.authorizeHandler(w, r)
	default:
		http.NotFound(w, r)
	}
}

// metadataHandler は GET /.well-known/oauth-authorization-server を処理する。
// RFC 8414 準拠のメタデータ JSON を返す。
func (s *OAuthServer) metadataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	prefix := s.config.PathPrefix
	baseURL := s.config.ExternalURL

	metadata := map[string]any{
		"issuer":                                baseURL,
		"authorization_endpoint":                baseURL + prefix + "/authorize",
		"token_endpoint":                        baseURL + prefix + "/token",
		"registration_endpoint":                 baseURL + prefix + "/register",
		"jwks_uri":                              baseURL + prefix + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":       []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(metadata)
}

// jwksHandler は GET /.well-known/jwks.json を処理する。
// 公開鍵を JWK Set として返す。
func (s *OAuthServer) jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pub := s.privateKey.PublicKey

	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "EC",
				"kid": s.keyID,
				"crv": "P-256",
				"x":   base64.RawURLEncoding.EncodeToString(padTo32Bytes(pub.X)),
				"y":   base64.RawURLEncoding.EncodeToString(padTo32Bytes(pub.Y)),
				"use": "sig",
				"alg": "ES256",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(jwks)
}

// computeKeyID は ECDSA 公開鍵から SHA-256 サムプリントベースの kid を生成する。
func computeKeyID(pub *ecdsa.PublicKey) string {
	// JWK Thumbprint (RFC 7638) の簡易版: x||y の SHA-256
	xBytes := padTo32Bytes(pub.X)
	yBytes := padTo32Bytes(pub.Y)
	h := sha256.New()
	h.Write(xBytes)
	h.Write(yBytes)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:8])
}

// padTo32Bytes は big.Int を 32バイト固定長にゼロパディングする。
// P-256 の座標エンコードに使用する。
func padTo32Bytes(n *big.Int) []byte {
	b := n.Bytes()
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

// authorizeHandler は GET /authorize を処理する。
//
//  1. パラメータ検証（response_type, client_id, redirect_uri, code_challenge, code_challenge_method, state, scope）
//  2. ユーザー認証確認（セッション Cookie）
//  3. 未認証ならログインにリダイレクト（元 URL をクエリパラメータで渡す）
//  4. 認証済みなら認可コード生成 → redirect_uri にリダイレクト
func (s *OAuthServer) authorizeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()

	// --- パラメータ検証 ---

	// response_type は "code" 必須
	if q.Get("response_type") != "code" {
		s.authorizeError(w, "invalid_request", "response_type must be 'code'", http.StatusBadRequest)
		return
	}

	// client_id 検証
	clientID := q.Get("client_id")
	if clientID == "" {
		s.authorizeError(w, "invalid_request", "client_id is required", http.StatusBadRequest)
		return
	}
	if s.config.OAuth != nil && s.config.OAuth.ClientID != "" {
		if clientID != s.config.OAuth.ClientID {
			s.authorizeError(w, "invalid_client", "unknown client_id", http.StatusBadRequest)
			return
		}
	}

	// redirect_uri 検証
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		s.authorizeError(w, "invalid_request", "redirect_uri is required", http.StatusBadRequest)
		return
	}
	if !s.isAllowedRedirectURI(redirectURI) {
		s.authorizeError(w, "invalid_request", "redirect_uri is not allowed", http.StatusBadRequest)
		return
	}

	// code_challenge 必須（PKCE）
	codeChallenge := q.Get("code_challenge")
	if codeChallenge == "" {
		s.authorizeError(w, "invalid_request", "code_challenge is required", http.StatusBadRequest)
		return
	}

	// code_challenge_method は "S256" 必須
	codeChallengeMethod := q.Get("code_challenge_method")
	if codeChallengeMethod != "S256" {
		s.authorizeError(w, "invalid_request", "code_challenge_method must be 'S256'", http.StatusBadRequest)
		return
	}

	// state 必須
	state := q.Get("state")
	if state == "" {
		s.authorizeError(w, "invalid_request", "state is required", http.StatusBadRequest)
		return
	}

	// scope に "openid" を含む
	scope := q.Get("scope")
	if !strings.Contains(scope, "openid") {
		s.authorizeError(w, "invalid_scope", "scope must include 'openid'", http.StatusBadRequest)
		return
	}

	// --- ユーザー認証確認 ---
	if s.sessionManager == nil {
		http.Error(w, "session manager not configured", http.StatusInternalServerError)
		return
	}

	sess, err := s.sessionManager.GetSessionFromRequest(r.Context(), r)
	if err != nil {
		// Cookie が無効（改ざん等）: ログインへリダイレクト
		s.redirectToLogin(w, r)
		return
	}
	if sess == nil || time.Now().After(sess.ExpiresAt) {
		// 未認証またはセッション期限切れ: ログインへリダイレクト
		s.redirectToLogin(w, r)
		return
	}

	// --- 認証済み: 認可コード生成 ---
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	code := hex.EncodeToString(codeBytes)

	// スコープをパース
	scopes := strings.Fields(scope)

	// AuthCodeData を構築して Store に保存
	ttl := s.config.AuthCodeTTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	now := time.Now()
	authCodeData := &AuthCodeData{
		Code:                code,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Scopes:              scopes,
		User:                sess.User,
		CreatedAt:           now,
		ExpiresAt:           now.Add(ttl),
		Used:                false,
	}

	if err := s.store.SetAuthCode(r.Context(), code, authCodeData, ttl); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// redirect_uri にリダイレクト（code, state をクエリパラメータで付加）
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	rq := redirectURL.Query()
	rq.Set("code", code)
	rq.Set("state", state)
	redirectURL.RawQuery = rq.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// authorizeError は OAuth 2.1 の error レスポンスを JSON で返す。
func (s *OAuthServer) authorizeError(w http.ResponseWriter, errorCode, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
}

// isAllowedRedirectURI は redirect_uri が許可リストに含まれるかを判定する。
// AllowedRedirectURIs が空の場合、localhost の URI のみ許可する。
func (s *OAuthServer) isAllowedRedirectURI(uri string) bool {
	if s.config.OAuth != nil && len(s.config.OAuth.AllowedRedirectURIs) > 0 {
		for _, allowed := range s.config.OAuth.AllowedRedirectURIs {
			if uri == allowed {
				return true
			}
		}
		return false
	}
	// AllowedRedirectURIs 未設定の場合: localhost のみ許可
	parsed, err := url.Parse(uri)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// redirectToLogin は未認証ユーザーをログインページにリダイレクトする。
// 元の /authorize リクエスト URL を redirect_to パラメータで渡す。
func (s *OAuthServer) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	originalURL := r.URL.String()
	loginURL := fmt.Sprintf("%s/login?redirect_to=%s", s.config.PathPrefix, url.QueryEscape(originalURL))
	http.Redirect(w, r, loginURL, http.StatusFound)
}
