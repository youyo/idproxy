package idproxy

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// BearerValidator は Bearer JWT アクセストークンを検証する。
// JWT の署名検証、クレーム検証、Store でのリボケーションチェックを行い、
// 認証済みの User を返す。
type BearerValidator struct {
	store     Store
	publicKey *ecdsa.PublicKey
	issuer    string
	parser    *jwt.Parser
}

// NewBearerValidator は BearerValidator を構築する。
// Config.OAuth が nil の場合、または SigningKey が ECDSA でない場合はエラーを返す。
func NewBearerValidator(cfg Config, store Store) (*BearerValidator, error) {
	if cfg.OAuth == nil {
		return nil, errors.New("bearer validator requires OAuth config with signing key")
	}

	signingKey := cfg.OAuth.SigningKey
	ecKey, ok := signingKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("bearer validator requires ECDSA signing key (ES256)")
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithIssuer(cfg.ExternalURL),
		jwt.WithAudience(cfg.ExternalURL),
		jwt.WithExpirationRequired(),
	)

	return &BearerValidator{
		store:     store,
		publicKey: &ecKey.PublicKey,
		issuer:    cfg.ExternalURL,
		parser:    parser,
	}, nil
}

// Validate は Bearer トークン文字列を検証し、認証済み User を返す。
// 無効な場合は error を返す。
//
// 検証手順:
//  1. JWT をパースし ES256 公開鍵で署名検証（exp, iss, aud は parser が自動検証）
//  2. jti クレームの存在確認
//  3. email クレームの存在確認
//  4. Store でリボケーションチェック（jti で検索）
//  5. 成功時: User を構築して返す
func (v *BearerValidator) Validate(ctx context.Context, tokenStr string) (*User, error) {
	// 1. JWT パース + 署名検証 + exp/iss 検証
	token, err := v.parser.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return v.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid bearer token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid bearer token: failed to extract claims")
	}

	// 2. jti クレームの存在確認
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, errors.New("invalid bearer token: missing jti claim")
	}

	// 3. email クレームの存在確認
	email, _ := claims["email"].(string)
	if email == "" {
		return nil, errors.New("invalid bearer token: missing email claim")
	}

	// 4. Store でリボケーションチェック
	tokenData, err := v.store.GetAccessToken(ctx, jti)
	if err != nil {
		return nil, fmt.Errorf("bearer token store lookup failed: %w", err)
	}
	if tokenData == nil {
		return nil, errors.New("invalid bearer token: token not found in store")
	}
	if tokenData.Revoked {
		return nil, errors.New("invalid bearer token: token has been revoked")
	}

	// 5. User を構築
	sub, _ := claims["sub"].(string)
	name, _ := claims["name"].(string)

	user := &User{
		Email:   email,
		Name:    name,
		Subject: sub,
		Issuer:  v.issuer,
	}

	return user, nil
}
