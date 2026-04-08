package idproxy

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Auth はリクエスト認証ミドルウェアのメインエントリポイント。
// Wrap() で http.Handler をラップし、リクエストの種類に応じて
// OAuth AS / Bearer 検証 / セッション検証 / ブラウザリダイレクト / 401 を判定する。
type Auth struct {
	config          Config
	providerManager *ProviderManager
	sessionManager  *SessionManager
	browserAuth     *BrowserAuth
	store           Store
	// oauthServer は M14-M17 で設定する OAuth 2.1 AS ハンドラー。
	// nil の場合、OAuth AS パスへのリクエストは 501 を返す。
	oauthServer http.Handler
	logger      *slog.Logger
}

// New は Auth を構築し、内部コンポーネント（ProviderManager, SessionManager, BrowserAuth）を初期化する。
func New(ctx context.Context, cfg Config) (*Auth, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	store := cfg.Store

	pm, err := NewProviderManager(ctx, cfg)
	if err != nil {
		return nil, err
	}

	sm, err := NewSessionManager(cfg)
	if err != nil {
		return nil, err
	}

	ba := NewBrowserAuth(cfg, pm, sm, store)

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Auth{
		config:          cfg,
		providerManager: pm,
		sessionManager:  sm,
		browserAuth:     ba,
		store:           store,
		logger:          logger,
	}, nil
}

// SetOAuthServer は OAuth 2.1 AS ハンドラーを設定する。
// M14-M17 で構築した OAuthServer を Wrap() の前に設定する。
func (a *Auth) SetOAuthServer(h http.Handler) {
	a.oauthServer = h
}

// Wrap は認証ミドルウェアを返す。
//
// リクエスト判定ロジック:
//  1. BrowserAuth パス（/login, /callback, /select） → BrowserAuth に委譲
//  2. OAuth AS パス（/.well-known/*, /register, /authorize, /token） → OAuthServer に委譲
//  3. Authorization: Bearer ヘッダー → JWT 検証（M13 でスタブから本実装へ）
//  4. セッション Cookie → SessionManager でセッション検証、User をコンテキストに注入
//  5. Accept: text/html を含むブラウザリクエスト → ログインページへリダイレクト
//  6. その他 API リクエスト → 401 Unauthorized
func (a *Auth) Wrap(next http.Handler) http.Handler {
	prefix := a.config.PathPrefix

	// BrowserAuth のハンドラーを事前構築
	loginHandler := a.browserAuth.LoginHandler()
	callbackHandler := a.browserAuth.CallbackHandler()
	selectionHandler := a.browserAuth.SelectionHandler()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// 1. BrowserAuth パス判定
		switch path {
		case prefix + "/login":
			loginHandler.ServeHTTP(w, r)
			return
		case prefix + "/callback":
			callbackHandler.ServeHTTP(w, r)
			return
		case prefix + "/select":
			selectionHandler.ServeHTTP(w, r)
			return
		}

		// 2. OAuth AS パス判定
		if a.isOAuthASPath(path) {
			if a.oauthServer == nil {
				http.Error(w, "OAuth 2.1 AS is not configured", http.StatusNotImplemented)
				return
			}
			a.oauthServer.ServeHTTP(w, r)
			return
		}

		// 3. Bearer トークン判定
		if token := extractBearerToken(r); token != "" {
			// M13 で JWT 検証を実装予定。今はスタブで 401 を返す。
			a.logger.Debug("bearer token received, JWT verification not yet implemented")
			http.Error(w, "bearer token verification not implemented", http.StatusUnauthorized)
			return
		}

		// 4. セッション Cookie 判定
		sess, err := a.sessionManager.GetSessionFromRequest(r.Context(), r)
		if err != nil {
			// Cookie が無効（改ざん等）
			a.logger.Warn("invalid session cookie", "error", err)
			a.handleUnauthenticated(w, r)
			return
		}
		if sess != nil {
			// セッションの有効期限チェック
			if time.Now().After(sess.ExpiresAt) {
				a.logger.Debug("session expired", "session_id", sess.ID)
				a.handleUnauthenticated(w, r)
				return
			}

			// 認証済み: User をコンテキストに注入して next に委譲
			ctx := newContextWithUser(r.Context(), sess.User)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// 5. & 6. 未認証リクエスト
		a.handleUnauthenticated(w, r)
	})
}

// isOAuthASPath はパスが OAuth AS エンドポイントに該当するかを判定する。
func (a *Auth) isOAuthASPath(path string) bool {
	prefix := a.config.PathPrefix

	oauthPaths := []string{
		prefix + "/register",
		prefix + "/authorize",
		prefix + "/token",
	}

	for _, p := range oauthPaths {
		if path == p {
			return true
		}
	}

	// /.well-known/ プレフィックスのパス
	wellKnownPrefix := prefix + "/.well-known/"
	if strings.HasPrefix(path, wellKnownPrefix) {
		return true
	}

	return false
}

// handleUnauthenticated は未認証リクエストに対して
// ブラウザリクエストならリダイレクト、API リクエストなら 401 を返す。
func (a *Auth) handleUnauthenticated(w http.ResponseWriter, r *http.Request) {
	if isBrowserRequest(r) {
		// ブラウザリクエスト: ログインページにリダイレクト
		redirectTo := r.URL.RequestURI()
		loginURL := a.config.PathPrefix + "/login?redirect_to=" + redirectTo
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}
	// API リクエスト: 401
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// extractBearerToken は Authorization ヘッダーから Bearer トークンを抽出する。
// ヘッダーが存在しないか Bearer 形式でない場合は空文字を返す。
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	const bearerPrefix = "Bearer "
	if len(auth) > len(bearerPrefix) && strings.EqualFold(auth[:len(bearerPrefix)], bearerPrefix) {
		return auth[len(bearerPrefix):]
	}
	return ""
}

// isBrowserRequest は Accept ヘッダーに text/html を含むかを判定する。
func isBrowserRequest(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/html")
}
