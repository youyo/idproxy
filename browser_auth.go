package idproxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// authState はブラウザ認証フローの state パラメータに紐づくデータ。
// Store の AuthCode エントリを再利用して保存する。
//
// マッピング:
//   - AuthCodeData.Code        → state 値
//   - AuthCodeData.RedirectURI → 元の URL（認証後のリダイレクト先）
//   - AuthCodeData.CodeChallenge → nonce
//   - AuthCodeData.CodeChallengeMethod → provider の Issuer URL
//   - AuthCodeData.ClientID    → "browser-auth-state"（識別用マーカー）
const browserAuthStateMarker = "browser-auth-state"

// BrowserAuth はブラウザベースの OIDC 認証フローを処理する。
// LoginHandler で IdP へのリダイレクトを行い、
// CallbackHandler で認可コードを ID Token に交換してセッションを発行する。
type BrowserAuth struct {
	pm             *ProviderManager
	sm             *SessionManager
	store          Store
	allowedDomains []string
	allowedEmails  []string
	externalURL    string
	pathPrefix     string
	logger         *slog.Logger
}

// NewBrowserAuth は新しい BrowserAuth を生成する。
func NewBrowserAuth(cfg Config, pm *ProviderManager, sm *SessionManager, store Store) *BrowserAuth {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &BrowserAuth{
		pm:             pm,
		sm:             sm,
		store:          store,
		allowedDomains: cfg.AllowedDomains,
		allowedEmails:  cfg.AllowedEmails,
		externalURL:    cfg.ExternalURL,
		pathPrefix:     cfg.PathPrefix,
		logger:         logger,
	}
}

// LoginHandler は GET /login を処理し、IdP へのリダイレクトを行う。
//
// クエリパラメータ:
//   - provider: 使用する IdP の Issuer URL（複数プロバイダー時に必須）
//   - redirect_to: 認証後のリダイレクト先 URL（デフォルト: "/"）
//
// 単一プロバイダーの場合は provider パラメータを省略可能。
func (ba *BrowserAuth) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// プロバイダーを決定
		issuer := r.URL.Query().Get("provider")
		if issuer == "" {
			// 単一プロバイダーなら自動選択
			entry, ok := ba.pm.Single()
			if !ok {
				http.Error(w, "provider parameter is required", http.StatusBadRequest)
				return
			}
			issuer = entry.config.Issuer
		}

		// プロバイダーが存在するか確認
		_, ok := ba.pm.Get(issuer)
		if !ok {
			http.Error(w, "unknown provider", http.StatusBadRequest)
			return
		}

		oauth2Cfg, err := ba.pm.OAuth2Config(issuer)
		if err != nil {
			ba.logger.Error("failed to get oauth2 config", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		// state / nonce を生成
		state, err := generateRandomHex(32)
		if err != nil {
			ba.logger.Error("failed to generate state", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		nonce, err := generateRandomHex(32)
		if err != nil {
			ba.logger.Error("failed to generate nonce", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		// 元の URL を取得
		redirectTo := r.URL.Query().Get("redirect_to")
		if redirectTo == "" {
			redirectTo = "/"
		}

		// state を Store に保存（AuthCodeData を再利用）
		stateData := &AuthCodeData{
			Code:                state,
			ClientID:            browserAuthStateMarker,
			RedirectURI:         redirectTo,
			CodeChallenge:       nonce,
			CodeChallengeMethod: issuer,
			CreatedAt:           time.Now(),
			ExpiresAt:           time.Now().Add(10 * time.Minute),
		}
		if err := ba.store.SetAuthCode(ctx, state, stateData, 10*time.Minute); err != nil {
			ba.logger.Error("failed to store state", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		// IdP にリダイレクト
		authURL := oauth2Cfg.AuthCodeURL(state,
			oauth2.SetAuthURLParam("nonce", nonce),
			oauth2.SetAuthURLParam("response_type", "code"),
		)

		http.Redirect(w, r, authURL, http.StatusFound)
	})
}

// CallbackHandler は GET /callback を処理する。
// IdP からの認可コードを ID Token に交換し、セッションを発行して元の URL にリダイレクトする。
func (ba *BrowserAuth) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		q := r.URL.Query()

		// IdP からのエラー応答を処理
		if errParam := q.Get("error"); errParam != "" {
			desc := q.Get("error_description")
			ba.logger.Warn("IdP returned error",
				"error", errParam,
				"error_description", desc,
			)
			http.Error(w, fmt.Sprintf("authentication failed: %s", errParam), http.StatusForbidden)
			return
		}

		code := q.Get("code")
		state := q.Get("state")

		if code == "" {
			http.Error(w, "missing code parameter", http.StatusBadRequest)
			return
		}
		if state == "" {
			http.Error(w, "missing state parameter", http.StatusBadRequest)
			return
		}

		// state を検証
		stateData, err := ba.store.GetAuthCode(ctx, state)
		if err != nil {
			ba.logger.Error("failed to get state from store", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if stateData == nil || stateData.ClientID != browserAuthStateMarker {
			http.Error(w, "invalid or expired state", http.StatusBadRequest)
			return
		}

		// state を削除（使い捨て）
		_ = ba.store.DeleteAuthCode(ctx, state)

		nonce := stateData.CodeChallenge
		issuer := stateData.CodeChallengeMethod
		redirectTo := stateData.RedirectURI

		// OAuth2 Config を取得
		oauth2Cfg, err := ba.pm.OAuth2Config(issuer)
		if err != nil {
			ba.logger.Error("failed to get oauth2 config for issuer", "issuer", issuer, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		// 認可コードをトークンに交換
		token, err := oauth2Cfg.Exchange(ctx, code)
		if err != nil {
			ba.logger.Error("failed to exchange code for token", "error", err)
			http.Error(w, "failed to exchange authorization code", http.StatusBadRequest)
			return
		}

		// ID Token を取得
		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok || rawIDToken == "" {
			ba.logger.Error("no id_token in token response")
			http.Error(w, "missing id_token in response", http.StatusBadRequest)
			return
		}

		// ID Token を検証
		verifier, err := ba.pm.Verifier(issuer)
		if err != nil {
			ba.logger.Error("failed to get verifier", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			ba.logger.Error("failed to verify id_token", "error", err)
			http.Error(w, "invalid id_token", http.StatusBadRequest)
			return
		}

		// nonce 検証
		if idToken.Nonce != nonce {
			ba.logger.Error("nonce mismatch",
				"expected", nonce,
				"got", idToken.Nonce,
			)
			http.Error(w, "nonce mismatch", http.StatusBadRequest)
			return
		}

		// クレームを抽出
		var claims struct {
			Email string `json:"email"`
			Name  string `json:"name"`
		}
		if err := idToken.Claims(&claims); err != nil {
			ba.logger.Error("failed to extract claims", "error", err)
			http.Error(w, "failed to extract claims", http.StatusInternalServerError)
			return
		}

		// AllowedDomains / AllowedEmails 認可判定
		if !isEmailAuthorized(claims.Email, ba.allowedDomains, ba.allowedEmails) {
			ba.logger.Warn("email not authorized",
				"email", claims.Email,
				"allowed_domains", ba.allowedDomains,
				"allowed_emails", ba.allowedEmails,
			)
			http.Error(w, "email not authorized", http.StatusForbidden)
			return
		}

		// 全クレームを取得
		var allClaims map[string]interface{}
		_ = idToken.Claims(&allClaims)

		// User を構築
		user := &User{
			Email:   claims.Email,
			Name:    claims.Name,
			Subject: idToken.Subject,
			Issuer:  idToken.Issuer,
			Claims:  allClaims,
		}

		// セッションを発行
		sess, err := ba.sm.IssueSession(ctx, user, issuer, rawIDToken)
		if err != nil {
			ba.logger.Error("failed to issue session", "error", err)
			http.Error(w, "failed to create session", http.StatusInternalServerError)
			return
		}

		// Cookie を設定
		if err := ba.sm.SetCookie(w, sess.ID); err != nil {
			ba.logger.Error("failed to set cookie", "error", err)
			http.Error(w, "failed to set cookie", http.StatusInternalServerError)
			return
		}

		// 元の URL にリダイレクト
		http.Redirect(w, r, redirectTo, http.StatusFound)
	})
}

// SelectionHandler は複数 IdP 時のプロバイダー選択ページを表示する。
// 単一プロバイダーの場合は /login に直接リダイレクトする。
func (ba *BrowserAuth) SelectionHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ba.pm.Count() == 1 {
			loginURL := ba.pathPrefix + "/login"
			// redirect_to パラメータがあればそのまま渡す
			if rt := r.URL.Query().Get("redirect_to"); rt != "" {
				loginURL += "?redirect_to=" + rt
			}
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, ba.pm.SelectionHTML())
	})
}

// isEmailAuthorized はメールアドレスが AllowedDomains / AllowedEmails で許可されているかを判定する。
// AllowedDomains と AllowedEmails の両方が空の場合は全てのメールを許可する。
// AllowedDomains と AllowedEmails は OR 条件で評価される。
func isEmailAuthorized(email string, allowedDomains, allowedEmails []string) bool {
	if len(allowedDomains) == 0 && len(allowedEmails) == 0 {
		return true
	}

	if email == "" {
		return false
	}

	emailLower := strings.ToLower(email)

	// AllowedEmails でのチェック（完全一致）
	for _, allowed := range allowedEmails {
		if emailLower == strings.ToLower(allowed) {
			return true
		}
	}

	// AllowedDomains でのチェック（メールのドメイン部分）
	parts := strings.SplitN(emailLower, "@", 2)
	if len(parts) != 2 {
		return false
	}
	domain := parts[1]
	for _, allowed := range allowedDomains {
		if domain == strings.ToLower(allowed) {
			return true
		}
	}

	return false
}

// generateRandomHex は暗号論的乱数で n バイトの乱数を生成し、hex エンコードした文字列を返す。
func generateRandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("idproxy: failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

