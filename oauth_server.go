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

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
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
	case prefix + "/token":
		s.tokenHandler(w, r)
	case prefix + "/register":
		s.registerHandler(w, r)
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

	// redirect_uri 検証
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		s.authorizeError(w, "invalid_request", "redirect_uri is required", http.StatusBadRequest)
		return
	}

	// client_id の検証: 静的設定 → 動的登録クライアント → デフォルト許可
	var dynamicClient *ClientData
	if s.config.OAuth != nil && s.config.OAuth.ClientID != "" {
		// 静的クライアント ID が設定されている場合
		if clientID != s.config.OAuth.ClientID {
			// 動的登録クライアントも確認
			client, err := s.store.GetClient(r.Context(), clientID)
			if err != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			if client == nil {
				s.authorizeError(w, "invalid_client", "unknown client_id", http.StatusBadRequest)
				return
			}
			dynamicClient = client
		}
	} else {
		// 静的クライアント ID 未設定: 動的登録クライアントを確認
		client, err := s.store.GetClient(r.Context(), clientID)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if client != nil {
			dynamicClient = client
		}
	}

	// redirect_uri 検証: 動的登録クライアントの場合は登録済み URI と照合
	if dynamicClient != nil {
		uriAllowed := false
		for _, u := range dynamicClient.RedirectURIs {
			if u == redirectURI {
				uriAllowed = true
				break
			}
		}
		if !uriAllowed {
			s.authorizeError(w, "invalid_request", "redirect_uri is not allowed", http.StatusBadRequest)
			return
		}
	} else if !s.isAllowedRedirectURI(redirectURI) {
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

// tokenHandler は POST /token を処理する。
//
// OAuth 2.1 Token Endpoint:
//  1. Content-Type: application/x-www-form-urlencoded を検証
//  2. grant_type = "authorization_code" を確認
//  3. code, redirect_uri, client_id, code_verifier を取得
//  4. Store から認可コードを取得・削除（一回使用制約）
//  5. redirect_uri, client_id の一致検証
//  6. PKCE 検証
//  7. Access Token（JWT ES256）を生成・Store に保存
//  8. JSON レスポンス返却
func (s *OAuthServer) tokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Content-Type 検証
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		s.tokenError(w, "invalid_request", "Content-Type must be application/x-www-form-urlencoded", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		s.tokenError(w, "invalid_request", "failed to parse form", http.StatusBadRequest)
		return
	}

	// grant_type 検証
	grantType := r.PostFormValue("grant_type")
	if grantType != "authorization_code" {
		s.tokenError(w, "unsupported_grant_type", "grant_type must be 'authorization_code'", http.StatusBadRequest)
		return
	}

	code := r.PostFormValue("code")
	redirectURI := r.PostFormValue("redirect_uri")
	clientID := r.PostFormValue("client_id")
	codeVerifier := r.PostFormValue("code_verifier")

	if code == "" {
		s.tokenError(w, "invalid_request", "code is required", http.StatusBadRequest)
		return
	}
	if redirectURI == "" {
		s.tokenError(w, "invalid_request", "redirect_uri is required", http.StatusBadRequest)
		return
	}
	if clientID == "" {
		s.tokenError(w, "invalid_request", "client_id is required", http.StatusBadRequest)
		return
	}
	if codeVerifier == "" {
		s.tokenError(w, "invalid_request", "code_verifier is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// 認可コード取得
	authCode, err := s.store.GetAuthCode(ctx, code)
	if err != nil {
		s.tokenError(w, "server_error", "failed to retrieve authorization code", http.StatusInternalServerError)
		return
	}
	if authCode == nil {
		s.tokenError(w, "invalid_grant", "authorization code not found", http.StatusBadRequest)
		return
	}

	// 二重使用検出: Used フラグが true の場合、関連トークンを無効化
	if authCode.Used {
		// セキュリティ: 認可コードの二重使用はトークン漏洩の兆候
		// 関連する全アクセストークンを無効化すべき（ここでは Store から削除）
		s.tokenError(w, "invalid_grant", "authorization code has already been used", http.StatusBadRequest)
		return
	}

	// 認可コードを使用済みとマーク（一回使用制約）
	authCode.Used = true
	ttl := authCode.ExpiresAt.Sub(authCode.CreatedAt)
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if err := s.store.SetAuthCode(ctx, code, authCode, ttl); err != nil {
		s.tokenError(w, "server_error", "failed to update authorization code", http.StatusInternalServerError)
		return
	}

	// 有効期限チェック
	if time.Now().After(authCode.ExpiresAt) {
		s.tokenError(w, "invalid_grant", "authorization code has expired", http.StatusBadRequest)
		return
	}

	// redirect_uri, client_id の一致検証
	if authCode.RedirectURI != redirectURI {
		s.tokenError(w, "invalid_grant", "redirect_uri mismatch", http.StatusBadRequest)
		return
	}
	if authCode.ClientID != clientID {
		s.tokenError(w, "invalid_grant", "client_id mismatch", http.StatusBadRequest)
		return
	}

	// PKCE 検証
	if !VerifyS256(codeVerifier, authCode.CodeChallenge) {
		s.tokenError(w, "invalid_grant", "PKCE verification failed", http.StatusBadRequest)
		return
	}

	// Access Token（JWT ES256）を生成
	now := time.Now()
	expiresAt := now.Add(time.Hour)
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		s.tokenError(w, "server_error", "failed to generate token ID", http.StatusInternalServerError)
		return
	}
	jti := hex.EncodeToString(jtiBytes)

	email := ""
	sub := ""
	if authCode.User != nil {
		email = authCode.User.Email
		sub = authCode.User.Subject
	}

	claims := jwt.MapClaims{
		"jti":   jti,
		"iss":   s.config.ExternalURL,
		"aud":   s.config.ExternalURL,
		"sub":   sub,
		"email": email,
		"exp":   jwt.NewNumericDate(expiresAt),
		"iat":   jwt.NewNumericDate(now),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = s.keyID

	tokenStr, err := token.SignedString(s.privateKey)
	if err != nil {
		s.tokenError(w, "server_error", "failed to sign access token", http.StatusInternalServerError)
		return
	}

	// Store に AccessTokenData 保存
	tokenData := &AccessTokenData{
		JTI:       jti,
		Subject:   sub,
		Email:     email,
		ClientID:  clientID,
		Scopes:    authCode.Scopes,
		IssuedAt:  now,
		ExpiresAt: expiresAt,
		Revoked:   false,
	}
	if err := s.store.SetAccessToken(ctx, jti, tokenData, time.Hour); err != nil {
		s.tokenError(w, "server_error", "failed to store access token", http.StatusInternalServerError)
		return
	}

	// レスポンス JSON
	resp := map[string]any{
		"access_token": tokenStr,
		"token_type":   "Bearer",
		"expires_in":   3600,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// tokenError は /token エンドポイントの OAuth 2.1 error レスポンスを JSON で返す。
func (s *OAuthServer) tokenError(w http.ResponseWriter, errorCode, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
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

// registerHandler は POST /register を処理する。
// RFC 7591 Dynamic Client Registration に準拠し、クライアントを動的に登録する。
//
//  1. Content-Type: application/json を検証
//  2. リクエスト JSON をパース（redirect_uris 必須、client_name オプション）
//  3. redirect_uris のバリデーション（各 URI が有効か）
//  4. client_id を UUID で自動生成
//  5. Store.SetClient で保存
//  6. 201 Created でクライアント情報を返却
func (s *OAuthServer) registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Content-Type 検証
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		s.registerError(w, "invalid_request", "Content-Type must be application/json", http.StatusBadRequest)
		return
	}

	// リクエスト JSON パース
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
		Scope        string   `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.registerError(w, "invalid_request", "failed to parse JSON body", http.StatusBadRequest)
		return
	}

	// redirect_uris 必須・非空
	if len(req.RedirectURIs) == 0 {
		s.registerError(w, "invalid_request", "redirect_uris is required and must not be empty", http.StatusBadRequest)
		return
	}

	// redirect_uris バリデーション
	for _, uri := range req.RedirectURIs {
		parsed, err := url.Parse(uri)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			s.registerError(w, "invalid_request", fmt.Sprintf("invalid redirect_uri: %s", uri), http.StatusBadRequest)
			return
		}
	}

	// client_id を UUID で自動生成
	clientID := uuid.New().String()
	now := time.Now()

	clientData := &ClientData{
		ClientID:                clientID,
		ClientName:              req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   req.Scope,
		CreatedAt:               now,
	}

	// Store に保存
	if err := s.store.SetClient(r.Context(), clientID, clientData); err != nil {
		s.registerError(w, "server_error", "failed to store client", http.StatusInternalServerError)
		return
	}

	// レスポンス JSON（RFC 7591 準拠）
	resp := map[string]any{
		"client_id":                  clientData.ClientID,
		"redirect_uris":             clientData.RedirectURIs,
		"grant_types":               clientData.GrantTypes,
		"response_types":            clientData.ResponseTypes,
		"token_endpoint_auth_method": clientData.TokenEndpointAuthMethod,
	}
	if clientData.ClientName != "" {
		resp["client_name"] = clientData.ClientName
	}
	if clientData.Scope != "" {
		resp["scope"] = clientData.Scope
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// registerError は /register エンドポイントの error レスポンスを JSON で返す。
func (s *OAuthServer) registerError(w http.ResponseWriter, errorCode, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
}

// redirectToLogin は未認証ユーザーをログインページにリダイレクトする。
// 元の /authorize リクエスト URL を redirect_to パラメータで渡す。
func (s *OAuthServer) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	originalURL := r.URL.String()
	loginURL := fmt.Sprintf("%s/login?redirect_to=%s", s.config.PathPrefix, url.QueryEscape(originalURL))
	http.Redirect(w, r, loginURL, http.StatusFound)
}
