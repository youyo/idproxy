package idproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
)

// OAuthServer は OAuth 2.1 Authorization Server エンドポイントを提供する。
// RFC 8414 メタデータ、JWKS、および将来の /authorize, /token, /register を処理する。
type OAuthServer struct {
	config Config
	store  Store
	// privateKey は Access Token 署名用 ES256 秘密鍵。
	privateKey *ecdsa.PrivateKey
	// keyID は JWKS の kid フィールドに使用する鍵識別子。
	keyID string
}

// NewOAuthServer は OAuthServer を構築する。
// Config.OAuth が設定されている場合はその SigningKey（ECDSA P-256）を使用する。
// Config.OAuth が nil の場合は ES256 鍵ペアを自動生成する。
func NewOAuthServer(cfg Config, store Store) (*OAuthServer, error) {
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
		config:     cfg,
		store:      store,
		privateKey: privateKey,
		keyID:      keyID,
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
