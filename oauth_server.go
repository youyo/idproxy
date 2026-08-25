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
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
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
	// pm は IdP refresh_token を使って新しい id_token を取得するための ProviderManager。
	// nil の場合は IdP refresh をスキップして旧来の動作（古い IDToken を引き継ぐ）になる。
	pm *ProviderManager
	// accessTokenTTL は Access Token の有効期間。
	accessTokenTTL time.Duration
	// refreshTokenTTL は Refresh Token の有効期間。
	refreshTokenTTL time.Duration
	// logger は構造化ログ出力に使用する。
	logger *slog.Logger
	// cimd は URL 形式 client_id（CIMD）の解決に使用する。
	cimd *cimdFetcher
}

// NewOAuthServer は OAuthServer を構築する。
// Config.OAuth が設定されている場合はその SigningKey（ECDSA P-256）を使用する。
// Config.OAuth が nil の場合は ES256 鍵ペアを自動生成する。
// sm は SessionManager（/authorize でユーザー認証確認に使用）。nil の場合もエラーにはしない。
// pm は IdP refresh_token を使って id_token を更新するための ProviderManager。
// nil の場合は IdP refresh をスキップして旧来の動作（古い IDToken を引き継ぐ）になる。
func NewOAuthServer(cfg Config, store Store, sm *SessionManager, pm *ProviderManager) (*OAuthServer, error) {
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

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	accessTokenTTL := cfg.AccessTokenTTL
	if accessTokenTTL == 0 {
		accessTokenTTL = time.Hour
	}

	refreshTokenTTL := cfg.RefreshTokenTTL
	if refreshTokenTTL == 0 {
		refreshTokenTTL = 30 * 24 * time.Hour
	}

	return &OAuthServer{
		config:          cfg,
		store:           store,
		privateKey:      privateKey,
		keyID:           keyID,
		sessionManager:  sm,
		pm:              pm,
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
		logger:          logger,
		cimd:            newCIMDFetcher(denyInternalIP),
	}, nil
}

// protectedResourceMetadataPath は RFC 9728 が定める Protected Resource Metadata の
// well-known パス。resource identifier（ExternalURL）が path を持たないため、
// PathPrefix の有無に関わらずこの素のパスで提供する。
const protectedResourceMetadataPath = "/.well-known/oauth-protected-resource"

// supportedScopes は AS メタデータと Protected Resource Metadata の双方が広告する
// サポート scope の一覧。
var supportedScopes = []string{"openid", "email", "profile"}

// isProtectedResourceMetadataPath はパスが Protected Resource Metadata に該当するかを判定する。
// RFC 9728 準拠の素のパスに加え、既存 well-known 体系との互換のため
// PathPrefix 付きのパスも alias として受け付ける（PathPrefix が空なら両者は同一）。
func isProtectedResourceMetadataPath(prefix, path string) bool {
	return path == protectedResourceMetadataPath || path == prefix+protectedResourceMetadataPath
}

// ServeHTTP はリクエストを適切なハンドラーにルーティングする。
func (s *OAuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	prefix := s.config.PathPrefix

	// PathPrefix 付き alias と素のパスの 2 通りがあり switch の case では表現できないため、
	// switch の前に判定する。
	if isProtectedResourceMetadataPath(prefix, r.URL.Path) {
		s.protectedResourceMetadataHandler(w, r)
		return
	}

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
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      supportedScopes,
		// CIMD（MCP 2026-07-28）: URL 形式 client_id を受け付けることを広告する。
		"client_id_metadata_document_supported": true,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(metadata)
}

// protectedResourceMetadataHandler は GET /.well-known/oauth-protected-resource を処理する。
// RFC 9728 準拠の Protected Resource Metadata JSON を返す。
// idproxy 自身が AS を兼ねるため authorization_servers は自 issuer 1 件になる。
func (s *OAuthServer) protectedResourceMetadataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	baseURL := s.config.ExternalURL

	metadata := map[string]any{
		"resource":                 baseURL,
		"authorization_servers":    []string{baseURL},
		"scopes_supported":         supportedScopes,
		"bearer_methods_supported": []string{"header"},
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
				"kid": s.keyID,
				"crv": "P-256",
				"x":   base64.RawURLEncoding.EncodeToString(pubBytes[1:33]),
				"y":   base64.RawURLEncoding.EncodeToString(pubBytes[33:65]),
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
	ecdhPub, err := pub.ECDH()
	if err != nil {
		return ""
	}
	pubBytes := ecdhPub.Bytes() // 0x04 || X (32bytes) || Y (32bytes)
	h := sha256.New()
	h.Write(pubBytes[1:33])
	h.Write(pubBytes[33:65])
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:8])
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

	// client_id の検証: 静的設定 → CIMD → 動的登録クライアント → デフォルト許可
	hasStaticClientID := s.config.OAuth != nil && s.config.OAuth.ClientID != ""
	var dynamicClient *ClientData
	switch {
	case hasStaticClientID && clientID == s.config.OAuth.ClientID:
		// 静的クライアント ID と一致: 追加の解決は不要

	case isCIMDClientID(clientID):
		// URL 形式 client_id は CIMD として解決する。
		// ただし CIMD は運用者が明示的に有効化した場合にのみ受け付ける（デフォルト無効）。
		// 【重要・セキュリティ】metadata document は client_id の URL が指す第三者ホストが
		// 配布するため redirect_uris は攻撃者が自由に決められる。本実装には利用者同意
		// （consent）画面が無く、ログイン済みセッションがあれば /authorize は無言で
		// 認可コードを発行するため、無条件に受け付けると認可コード窃取に直結する。
		if !s.cimdClientsEnabled() {
			s.logger.Debug("cimd client rejected: AllowCIMDClients is disabled", "client_id", clientID)
			s.authorizeError(w, "invalid_client", "unknown client_id", http.StatusBadRequest)
			return
		}
		if !s.isAllowedCIMDHost(clientID) {
			s.logger.Debug("cimd client rejected: host is not allowed", "client_id", clientID)
			s.authorizeError(w, "invalid_client", "unknown client_id", http.StatusBadRequest)
			return
		}
		// fetch・検証の失敗はすべて invalid_client に潰し、静的 ClientID 未設定でも
		// デフォルト許可経路へ落とさない（fail-closed）。
		client, err := s.cimd.resolve(r.Context(), clientID)
		if err != nil {
			// 失敗理由は攻撃者への情報になるため応答本文には出さない。
			s.logger.Debug("cimd resolve failed", "client_id", clientID, "error", err)
			s.authorizeError(w, "invalid_client", "unknown client_id", http.StatusBadRequest)
			return
		}
		dynamicClient = client

	default:
		// 動的登録（DCR）クライアントを確認
		client, err := s.store.GetClient(r.Context(), clientID)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if client == nil && hasStaticClientID {
			s.authorizeError(w, "invalid_client", "unknown client_id", http.StatusBadRequest)
			return
		}
		dynamicClient = client
	}

	// redirect_uri 検証: 動的登録クライアントや CIMD クライアントの場合は
	// まずクライアント固有の登録済み URI と完全一致で照合する。
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
	}

	// 【重要・セキュリティ】運用者の許可リストはすべての経路で無条件に適用する。
	// 本実装には利用者同意（consent）画面が存在せず、ログイン済みセッションがあれば
	// /authorize は無言で認可コードを発行する。そのため「クライアント自身が申告した
	// redirect_uris」だけを信頼すると、攻撃者が自分の URI を持つクライアントを
	// CIMD document の公開や動的登録で用意するだけで認可コードを奪える
	// （攻撃者自身がクライアントなので PKCE は防御にならない）。
	// クライアント固有の照合に加えて運用者の許可リストも通ることを最終防衛線とする。
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

	// scope に "openid" を含む。
	// MCP クライアント（claude.ai 等）は openid を省略する場合があるため、
	// Gateway→IdP の脚では常に openid を付与して ID Token を取得できるよう自動補完する。
	//
	// 判定は空白区切りのトークン単位で行う（RFC 6749 §3.3）。
	// 部分一致で判定すると "notopenid" のような偽のスコープが openid とみなされ、
	// 自動補完がスキップされたまま AccessTokenData.Scopes に永続化されてしまう。
	scope := q.Get("scope")
	if !slices.Contains(strings.Fields(scope), "openid") {
		if scope == "" {
			scope = "openid"
		} else {
			scope = "openid " + scope
		}
	}

	// --- ユーザー認証確認 ---
	if s.sessionManager == nil {
		http.Error(w, "session manager not configured", http.StatusInternalServerError)
		return
	}

	sess, err := s.sessionManager.GetSessionFromRequest(r.Context(), r)
	// 診断ログ: authorize リクエスト
	s.logger.Info("oauth authorize", "client_id", clientID, "has_session", sess != nil)
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
	// StoreIDToken=true の場合、IDToken が期限切れなら強制再ログイン。
	// 古い IDToken を使って AccessTokenData.IDToken に期限切れトークンが伝播するのを防ぐ。
	if s.config.StoreIDToken && sess.IDToken != "" {
		// 署名検証なしで exp クレームだけ読む
		p := jwt.NewParser(jwt.WithoutClaimsValidation())
		if tok, _, err := p.ParseUnverified(sess.IDToken, jwt.MapClaims{}); err == nil {
			if exp, err := tok.Claims.GetExpirationTime(); err == nil && exp != nil {
				if time.Now().After(exp.Time) {
					s.logger.Info("oauth authorize: IDToken expired, forcing re-login",
						"client_id", clientID, "exp", exp.Time)
					s.redirectToLogin(w, r)
					return
				}
			}
		}
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
	// StoreIDToken が有効な場合、セッションの ID Token と IdP refresh_token を認可コードに伝播する。
	// authorization_code → access_token 経路で bearer 検証時に IDToken を復元するために使用。
	// IDPRefreshToken は refresh_token rotation 時の IdP refresh で新しい id_token を取得するために必要。
	if s.config.StoreIDToken && sess.IDToken != "" {
		authCodeData.IDToken = sess.IDToken
	}
	if s.config.StoreIDToken && sess.IDPRefreshToken != "" {
		authCodeData.IDPRefreshToken = sess.IDPRefreshToken
	}

	if err := s.store.SetAuthCode(r.Context(), code, authCodeData, ttl); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// redirect_uri にリダイレクト（code, state, iss をクエリパラメータで付加）
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	rq := redirectURL.Query()
	rq.Set("code", code)
	rq.Set("state", state)
	// RFC 9207: mix-up 攻撃対策として認可レスポンスに issuer 識別子を含める。
	// 値は AS メタデータの issuer（ExternalURL）と同一でなければならない。
	rq.Set("iss", s.config.ExternalURL)
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
//  2. grant_type = "authorization_code" または "refresh_token" に応じて処理
//  3. それぞれの検証・発行処理を行い JSON レスポンスを返す
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

	grantType := r.PostFormValue("grant_type")
	clientID := r.PostFormValue("client_id")

	// 診断ログ
	s.logger.Info("oauth token", "grant_type", grantType, "client_id", clientID)

	switch grantType {
	case "authorization_code":
		code := r.PostFormValue("code")
		redirectURI := r.PostFormValue("redirect_uri")
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

		// 二重使用検出: Used フラグが true の場合
		// セキュリティ: 認可コードの二重使用はコード漏洩の兆候であるため、
		// refresh_token の replay 検知と同じく、引き換え時に払い出したトークンファミリーを
		// tombstone で失効させ、認可コード自体も Store から削除する（RFC 6749 §4.1.2）。
		if authCode.Used {
			if authCode.FamilyID != "" {
				_ = s.store.SetFamilyRevocation(ctx, authCode.FamilyID, s.refreshTokenTTL)
			}
			// 認可コード値やトークン値はログに出さない。
			s.logger.Warn("oauth authorization code reuse detected",
				"family_id", authCode.FamilyID, "client_id", authCode.ClientID)
			if err := s.store.DeleteAuthCode(ctx, code); err != nil {
				s.logger.Warn("failed to delete reused authorization code", "error", err.Error())
			}
			s.tokenError(w, "invalid_grant", "authorization code has already been used", http.StatusBadRequest)
			return
		}

		// 認可コードを使用済みとマークし、発行するトークンファミリーを記録する（一回使用制約）。
		// FamilyID を先に確定させることで、二重使用検知時に失効対象のファミリーを特定できる。
		//
		// 既知の残課題: ここは Get → チェック → Set の非アトミックな更新であり、
		// 同一コードの同時引き換えを取りこぼす TOCTOU レースが残っている。
		// 解消には Store インターフェースにアトミックな消費操作
		//（ConsumeRefreshToken 相当）を追加する必要があるため、別途対応する。
		familyID := uuid.NewString()
		authCode.Used = true
		authCode.FamilyID = familyID
		codeTTL := authCode.ExpiresAt.Sub(authCode.CreatedAt)
		if codeTTL <= 0 {
			codeTTL = 5 * time.Minute
		}
		if err := s.store.SetAuthCode(ctx, code, authCode, codeTTL); err != nil {
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

		// ユーザー情報を取り出す
		user := authCode.User
		if user == nil {
			user = &User{}
		}

		// access_token + refresh_token を発行して応答（認可コードに記録した新 family）
		// IDPRefreshToken も引き継ぐことで refresh_token rotation 時の IdP refresh が可能になる。
		s.issueTokenResponse(w, r, user, authCode.Scopes, clientID, familyID, authCode.IDToken, authCode.IDPRefreshToken)

	case "refresh_token":
		refreshToken := r.PostFormValue("refresh_token")
		if refreshToken == "" {
			s.tokenError(w, "invalid_request", "refresh_token is required", http.StatusBadRequest)
			return
		}

		ctx := r.Context()

		// refresh_token を消費
		data, err := s.store.ConsumeRefreshToken(ctx, refreshToken)
		if err != nil {
			if errors.Is(err, ErrRefreshTokenAlreadyConsumed) {
				// replay 検知: family tombstone を書き込む
				if data != nil {
					_ = s.store.SetFamilyRevocation(ctx, data.FamilyID, s.refreshTokenTTL)
					s.logger.Warn("oauth refresh replay detected", "family_id", data.FamilyID, "client_id", data.ClientID)
				}
				s.tokenError(w, "invalid_grant", "refresh token has already been used", http.StatusBadRequest)
				return
			}
			s.tokenError(w, "server_error", "failed to consume refresh token", http.StatusInternalServerError)
			return
		}
		if data == nil {
			// 未登録または TTL 切れ
			s.tokenError(w, "invalid_grant", "refresh token not found or expired", http.StatusBadRequest)
			return
		}

		// family revocation チェック
		revoked, err := s.store.IsFamilyRevoked(ctx, data.FamilyID)
		if err != nil {
			s.tokenError(w, "server_error", "failed to check family revocation", http.StatusInternalServerError)
			return
		}
		if revoked {
			s.tokenError(w, "invalid_grant", "refresh token family has been revoked", http.StatusBadRequest)
			return
		}

		// client_id チェック
		if data.ClientID != clientID {
			s.tokenError(w, "invalid_grant", "client_id mismatch", http.StatusBadRequest)
			return
		}

		// ユーザー情報を再構築（OIDCIssuer を引き継いで principal_id を一致させる）
		user := &User{
			Email:   data.Email,
			Name:    data.Name,
			Subject: data.Subject,
			Issuer:  data.OIDCIssuer,
		}

		// rotation 成功ログ（replay 検知ログと対称）
		s.logger.Info("oauth refresh rotation",
			"family_id", data.FamilyID,
			"client_id", data.ClientID,
			"scope", strings.Join(data.Scopes, " "),
		)

		// 既存の familyID を引き継いで新 access_token + refresh_token を発行
		// StoreIDToken=true の場合のみ IDToken を引き継ぐ。
		// false に切り替えた後は既存 family でも IDToken を伝播しない。
		idTokenForRefresh := ""
		idpRefreshTokenForRefresh := ""

		if s.config.StoreIDToken {
			if data.IDPRefreshToken != "" && s.pm != nil {
				// IdP refresh_token を使って新しい id_token を取得する（Entra ID の id_token 有効期限対策）。
				oauth2Cfg, err := s.pm.OAuth2Config(data.OIDCIssuer)
				if err != nil {
					// OIDCIssuer が不明な場合（設定変更等）は再認証を強制する。
					s.tokenError(w, "invalid_grant", "provider not found, re-authenticate required", http.StatusBadRequest)
					return
				}

				// 既存の IdP refresh_token で新トークンを取得する。
				// oauth2.TokenSource は grant_type=refresh_token を自動発行する。
				ts := oauth2Cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: data.IDPRefreshToken})
				newToken, err := ts.Token()
				if err != nil {
					// IdP refresh 失敗（期限切れ、revoked 等）は再認証を強制する。
					s.logger.Warn("IdP refresh_token rejected, forcing re-authentication",
						"error", err.Error(), "user_sub", data.Subject)
					s.tokenError(w, "invalid_grant", "IdP token refresh failed, re-authenticate required", http.StatusBadRequest)
					return
				}

				// 新 id_token を取得する。
				if rawIDToken, ok := newToken.Extra("id_token").(string); ok && rawIDToken != "" {
					idTokenForRefresh = rawIDToken
				} else {
					// id_token が返らなかった場合（スコープ不足等）は警告のみ。
					// AccessTokenData.IDToken は空になり、次回アクセスで再認証が必要になる。
					s.logger.Warn("IdP refresh did not return id_token", "user_sub", data.Subject)
				}

				// 新 IdP refresh_token を保存する（Entra ID は毎回 rotate する）。
				if newToken.RefreshToken != "" {
					idpRefreshTokenForRefresh = newToken.RefreshToken
				} else {
					// refresh_token が返らない場合（一部 IdP）は既存を引き継ぐ。
					idpRefreshTokenForRefresh = data.IDPRefreshToken
				}
			} else {
				// IDPRefreshToken がない場合（旧セッション互換）は旧来の動作（古い IDToken を引き継ぐ）。
				idTokenForRefresh = data.IDToken
			}
		}
		s.issueTokenResponse(w, r, user, data.Scopes, data.ClientID, data.FamilyID, idTokenForRefresh, idpRefreshTokenForRefresh)

	default:
		s.tokenError(w, "unsupported_grant_type", "unsupported grant_type", http.StatusBadRequest)
	}
}

// issueTokenResponse は access_token + refresh_token を発行し応答を書く。
// familyID が空文字列の場合は新規生成する（authorization_code 経路）。
// 非空の場合は既存を引き継ぐ（refresh_token 経路）。
// idToken は authorization_code 経路で StoreIDToken=true のとき非空になる。
// idpRefreshToken は IdP が発行した refresh_token。取得できない場合は "" を渡す。
func (s *OAuthServer) issueTokenResponse(w http.ResponseWriter, r *http.Request, user *User, scopes []string, clientID string, familyID string, idToken, idpRefreshToken string) {
	ctx := r.Context()

	// familyID が空なら新規生成
	if familyID == "" {
		familyID = uuid.NewString()
	}

	email := user.Email
	sub := user.Subject
	name := user.Name

	// Access Token（JWT ES256）を生成
	now := time.Now()
	expiresAt := now.Add(s.accessTokenTTL)
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		s.tokenError(w, "server_error", "failed to generate token ID", http.StatusInternalServerError)
		return
	}
	jti := hex.EncodeToString(jtiBytes)

	claims := jwt.MapClaims{
		"jti":         jti,
		"iss":         s.config.ExternalURL,
		"aud":         s.config.ExternalURL,
		"sub":         sub,
		"email":       email,
		"oidc_issuer": user.Issuer,
		"exp":         jwt.NewNumericDate(expiresAt),
		"iat":         jwt.NewNumericDate(now),
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
		Scopes:    scopes,
		IssuedAt:  now,
		ExpiresAt: expiresAt,
		Revoked:   false,
		IDToken:   idToken,
	}
	if err := s.store.SetAccessToken(ctx, jti, tokenData, s.accessTokenTTL); err != nil {
		s.tokenError(w, "server_error", "failed to store access token", http.StatusInternalServerError)
		return
	}

	// Refresh Token 生成（opaque 32バイト base64url）
	rtBytes := make([]byte, 32)
	if _, err := rand.Read(rtBytes); err != nil {
		s.tokenError(w, "server_error", "failed to generate refresh token", http.StatusInternalServerError)
		return
	}
	refreshTokenID := base64.RawURLEncoding.EncodeToString(rtBytes)

	rtData := &RefreshTokenData{
		ID:              refreshTokenID,
		FamilyID:        familyID,
		ClientID:        clientID,
		Subject:         sub,
		OIDCIssuer:      user.Issuer,
		Email:           email,
		Name:            name,
		Scopes:          scopes,
		IssuedAt:        now,
		ExpiresAt:       now.Add(s.refreshTokenTTL),
		Used:            false,
		IDToken:         idToken,
		IDPRefreshToken: idpRefreshToken,
	}
	if err := s.store.SetRefreshToken(ctx, refreshTokenID, rtData, s.refreshTokenTTL); err != nil {
		s.tokenError(w, "server_error", "failed to store refresh token", http.StatusInternalServerError)
		return
	}

	// expires_in を秒数で計算
	expiresIn := int(s.accessTokenTTL.Seconds())

	// レスポンス JSON
	resp := map[string]any{
		"access_token":  tokenStr,
		"token_type":    "Bearer",
		"expires_in":    expiresIn,
		"refresh_token": refreshTokenID,
		"scope":         strings.Join(scopes, " "),
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

// cimdClientsEnabled は CIMD 形式 client_id の受け付けが有効かを返す。
// OAuth 設定が無い場合、および AllowCIMDClients 未設定の場合は無効（デフォルト安全）。
func (s *OAuthServer) cimdClientsEnabled() bool {
	return s.config.OAuth != nil && s.config.OAuth.AllowCIMDClients
}

// isAllowedCIMDHost は CIMD client_id のホストが許可リストに含まれるかを判定する。
// AllowedCIMDHosts が空の場合は（AllowCIMDClients による明示的な有効化を前提に）
// 任意のホストを許可する。
func (s *OAuthServer) isAllowedCIMDHost(clientID string) bool {
	if s.config.OAuth == nil || len(s.config.OAuth.AllowedCIMDHosts) == 0 {
		return true
	}
	parsed, err := url.Parse(clientID)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	for _, allowed := range s.config.OAuth.AllowedCIMDHosts {
		if host == strings.ToLower(allowed) {
			return true
		}
	}
	return false
}

// /register は未認証で叩けるため、リクエストの各要素に上限を設ける。
// Store には TTL も IP 単位の制限も無く、登録内容はそのまま永続化されるため、
// 上限が無いと 1 リクエストで任意サイズのデータを流し込めてしまう。
const (
	// registerMaxBodyBytes は POST /register のリクエストボディ上限。
	registerMaxBodyBytes = 8 << 10 // 8 KiB
	// registerMaxRedirectURIs は redirect_uris に指定できる最大件数。
	registerMaxRedirectURIs = 20
	// registerMaxRedirectURILen は redirect_uri 1 件あたりの最大長。
	registerMaxRedirectURILen = 2048
)

// registerHandler は POST /register を処理する。
// RFC 7591 Dynamic Client Registration に準拠し、クライアントを動的に登録する。
//
//  1. Content-Type: application/json を検証
//  2. リクエスト JSON をパース（redirect_uris 必須、client_name オプション）。
//     ボディは registerMaxBodyBytes までに制限する
//  3. redirect_uris のバリデーション（件数・各 URI の長さ・各 URI が有効か）
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
		RedirectURIs    []string `json:"redirect_uris"`
		ClientName      string   `json:"client_name"`
		Scope           string   `json:"scope"`
		ApplicationType string   `json:"application_type"`
	}
	// 未認証エンドポイントのためボディ長を制限する。
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, registerMaxBodyBytes)).Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.registerError(w, "invalid_request", fmt.Sprintf("request body must not exceed %d bytes", registerMaxBodyBytes), http.StatusRequestEntityTooLarge)
			return
		}
		s.registerError(w, "invalid_request", "failed to parse JSON body", http.StatusBadRequest)
		return
	}

	// redirect_uris 必須・非空
	if len(req.RedirectURIs) == 0 {
		s.registerError(w, "invalid_request", "redirect_uris is required and must not be empty", http.StatusBadRequest)
		return
	}
	if len(req.RedirectURIs) > registerMaxRedirectURIs {
		s.registerError(w, "invalid_request", fmt.Sprintf("redirect_uris must not contain more than %d entries", registerMaxRedirectURIs), http.StatusBadRequest)
		return
	}

	// redirect_uris バリデーション
	for _, uri := range req.RedirectURIs {
		if len(uri) > registerMaxRedirectURILen {
			s.registerError(w, "invalid_request", fmt.Sprintf("redirect_uri must not exceed %d bytes", registerMaxRedirectURILen), http.StatusBadRequest)
			return
		}
		parsed, err := url.Parse(uri)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			s.registerError(w, "invalid_request", fmt.Sprintf("invalid redirect_uri: %s", uri), http.StatusBadRequest)
			return
		}
	}

	// application_type（SEP-837）: 未指定なら "web" を既定とする。
	// RFC 7591 は未対応メタデータの無視を許容するため、未知の値でも登録は拒否せず
	// そのまま保存する（認可挙動には使わない）。
	applicationType := req.ApplicationType
	if applicationType == "" {
		applicationType = "web"
	} else if applicationType != "web" && applicationType != "native" {
		// 値そのものは攻撃者が任意長で指定できるためログに出さず、長さだけ記録する。
		s.logger.Debug("oauth register: unknown application_type", "length", len(applicationType))
	}

	// client_id を UUID で自動生成
	clientID := uuid.New().String()
	now := time.Now()

	clientData := &ClientData{
		ClientID:                clientID,
		ClientName:              req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   req.Scope,
		ApplicationType:         applicationType,
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
		"redirect_uris":              clientData.RedirectURIs,
		"grant_types":                clientData.GrantTypes,
		"response_types":             clientData.ResponseTypes,
		"token_endpoint_auth_method": clientData.TokenEndpointAuthMethod,
		"application_type":           clientData.ApplicationType,
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
//
// `PostLoginRedirectValidator` が設定済みの場合は escape 前の URL を Validator に通し、
// reject 時は 400 を返す（Phase D-3）。escape は既存通り `url.QueryEscape` を使う。
func (s *OAuthServer) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	originalURL := r.URL.String()
	if v := s.config.PostLoginRedirectValidator; v != nil {
		if vErr := callValidatorSafe(v, originalURL, s.logger, "oauth_redirect_to_login"); vErr != nil {
			s.logger.Warn("idproxy: post-login redirect rejected by validator",
				"redirect_to", originalURL,
				"error", vErr,
				"phase", "oauth_redirect_to_login",
			)
			http.Error(w, "invalid redirect_to", http.StatusBadRequest)
			return
		}
	}
	loginURL := fmt.Sprintf("%s/login?redirect_to=%s", s.config.PathPrefix, url.QueryEscape(originalURL))
	http.Redirect(w, r, loginURL, http.StatusFound)
}
