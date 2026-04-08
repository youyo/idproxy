package idproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/youyo/idproxy/testutil"
)

// setupAuth はテスト用の Auth を構築するヘルパー。
// MockIdP を起動し、内部コンポーネントを初期化して返す。
func setupAuth(t *testing.T, opts ...func(*Config)) (*Auth, *testutil.MockIdP) {
	t.Helper()

	idp := testutil.NewMockIdP(t)
	st := newTestMemoryStore()

	cfg := Config{
		Providers: []OIDCProvider{
			{
				Issuer:       idp.Issuer(),
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		},
		ExternalURL:  "http://localhost:8080",
		CookieSecret: []byte("test-cookie-secret-32-bytes-long!"),
		Store:        st,
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	a, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	return a, idp
}

// TestNew_Success は Auth の正常な構築を検証する。
func TestNew_Success(t *testing.T) {
	a, _ := setupAuth(t)
	if a == nil {
		t.Fatal("New() returned nil")
	}
}

// TestNew_InvalidConfig はバリデーションエラー時に New がエラーを返すことを検証する。
func TestNew_InvalidConfig(t *testing.T) {
	cfg := Config{} // 全フィールド未設定
	_, err := New(context.Background(), cfg)
	if err == nil {
		t.Fatal("New() should return error for invalid config")
	}
}

// --- Wrap() リクエスト判定テスト ---

// TestWrap_OAuthASPaths_WellKnown は OAuth AS パスへのリクエストが
// oauthServer に委譲されることを検証する（oauthServer が nil の場合は 501）。
func TestWrap_OAuthASPaths_WellKnown(t *testing.T) {
	a, _ := setupAuth(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for OAuth AS paths")
	})

	paths := []string{
		"/.well-known/oauth-authorization-server",
		"/register",
		"/authorize",
		"/token",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()

			a.Wrap(next).ServeHTTP(rec, req)

			if rec.Code != http.StatusNotImplemented {
				t.Errorf("expected 501 for %s (oauthServer=nil), got %d", path, rec.Code)
			}
		})
	}
}

// TestWrap_OAuthASPaths_WithPathPrefix は PathPrefix 付きの OAuth AS パスを検証する。
func TestWrap_OAuthASPaths_WithPathPrefix(t *testing.T) {
	a, _ := setupAuth(t, func(c *Config) {
		c.PathPrefix = "/auth"
	})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for OAuth AS paths")
	})

	paths := []string{
		"/auth/.well-known/oauth-authorization-server",
		"/auth/register",
		"/auth/authorize",
		"/auth/token",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()

			a.Wrap(next).ServeHTTP(rec, req)

			if rec.Code != http.StatusNotImplemented {
				t.Errorf("expected 501 for %s, got %d", path, rec.Code)
			}
		})
	}
}

// TestWrap_OAuthASPaths_WithOAuthServer は oauthServer が設定されている場合に
// リクエストが oauthServer に委譲されることを検証する。
func TestWrap_OAuthASPaths_WithOAuthServer(t *testing.T) {
	a, _ := setupAuth(t)

	oauthCalled := false
	a.oauthServer = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oauthCalled = true
		w.WriteHeader(http.StatusOK)
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	rec := httptest.NewRecorder()

	a.Wrap(next).ServeHTTP(rec, req)

	if !oauthCalled {
		t.Error("oauthServer should have been called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// TestWrap_BearerToken は Bearer トークン付きリクエストが
// 401 を返すことを検証する（M13 で JWT 検証を実装予定）。
func TestWrap_BearerToken(t *testing.T) {
	a, _ := setupAuth(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for Bearer token")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Authorization", "Bearer some-jwt-token")
	rec := httptest.NewRecorder()

	a.Wrap(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for Bearer token (stub), got %d", rec.Code)
	}
}

// TestWrap_SessionCookie_Valid はセッション Cookie 付きリクエストが
// next ハンドラーに委譲され、User がコンテキストに注入されることを検証する。
func TestWrap_SessionCookie_Valid(t *testing.T) {
	a, _ := setupAuth(t)

	// セッションを発行
	ctx := context.Background()
	user := &User{
		Email:   "test@example.com",
		Name:    "Test User",
		Subject: "sub-123",
		Issuer:  "https://accounts.google.com",
	}
	sess, err := a.sessionManager.IssueSession(ctx, user, user.Issuer, "fake-id-token")
	if err != nil {
		t.Fatalf("IssueSession() failed: %v", err)
	}

	// Cookie を設定するためのレコーダー
	cookieRec := httptest.NewRecorder()
	if err := a.sessionManager.SetCookie(cookieRec, sess.ID); err != nil {
		t.Fatalf("SetCookie() failed: %v", err)
	}
	cookieHeader := cookieRec.Header().Get("Set-Cookie")

	// next ハンドラーで User がコンテキストに存在するか確認
	var gotUser *User
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Cookie", cookieHeader)
	rec := httptest.NewRecorder()

	a.Wrap(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if gotUser == nil {
		t.Fatal("User should be injected into context")
	}
	if gotUser.Email != user.Email {
		t.Errorf("expected email %q, got %q", user.Email, gotUser.Email)
	}
	if gotUser.Subject != user.Subject {
		t.Errorf("expected subject %q, got %q", user.Subject, gotUser.Subject)
	}
}

// TestWrap_SessionCookie_Expired はセッション Cookie があるが
// セッションが Store に存在しない場合にブラウザリダイレクトを行うことを検証する。
func TestWrap_SessionCookie_Expired(t *testing.T) {
	a, _ := setupAuth(t)

	// セッションを発行してすぐ削除（期限切れシミュレーション）
	ctx := context.Background()
	user := &User{Email: "test@example.com"}
	sess, err := a.sessionManager.IssueSession(ctx, user, "https://example.com", "token")
	if err != nil {
		t.Fatalf("IssueSession() failed: %v", err)
	}

	cookieRec := httptest.NewRecorder()
	if err := a.sessionManager.SetCookie(cookieRec, sess.ID); err != nil {
		t.Fatalf("SetCookie() failed: %v", err)
	}
	cookieHeader := cookieRec.Header().Get("Set-Cookie")

	// Store からセッションを削除
	if err := a.store.DeleteSession(ctx, sess.ID); err != nil {
		t.Fatalf("DeleteSession() failed: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	})

	// ブラウザリクエスト（Accept: text/html）
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Cookie", cookieHeader)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rec := httptest.NewRecorder()

	a.Wrap(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 redirect for expired session with browser request, got %d", rec.Code)
	}
}

// TestWrap_BrowserRequest はブラウザリクエスト（Accept: text/html）が
// ログインページにリダイレクトされることを検証する。
func TestWrap_BrowserRequest(t *testing.T) {
	a, _ := setupAuth(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for browser request")
	})

	req := httptest.NewRequest(http.MethodGet, "/some/page", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml")
	rec := httptest.NewRecorder()

	a.Wrap(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 for browser request, got %d", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatal("Location header should not be empty")
	}
	// ログインパスを含むこと
	if !contains(loc, "/login") && !contains(loc, "/select") {
		t.Errorf("Location should contain login or select path, got %q", loc)
	}
}

// TestWrap_BrowserRequest_WithPathPrefix は PathPrefix 付きの
// ブラウザリクエストリダイレクトを検証する。
func TestWrap_BrowserRequest_WithPathPrefix(t *testing.T) {
	a, _ := setupAuth(t, func(c *Config) {
		c.PathPrefix = "/auth"
	})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/some/page", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()

	a.Wrap(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if !contains(loc, "/auth/login") && !contains(loc, "/auth/select") {
		t.Errorf("Location should contain /auth/login or /auth/select, got %q", loc)
	}
}

// TestWrap_APIRequest は API リクエスト（Accept に text/html を含まない）が
// 401 を返すことを検証する。
func TestWrap_APIRequest(t *testing.T) {
	a, _ := setupAuth(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for API request")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	a.Wrap(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for API request, got %d", rec.Code)
	}
}

// TestWrap_APIRequest_NoAcceptHeader は Accept ヘッダーなしのリクエストが
// 401 を返すことを検証する。
func TestWrap_APIRequest_NoAcceptHeader(t *testing.T) {
	a, _ := setupAuth(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	rec := httptest.NewRecorder()

	a.Wrap(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for request without Accept header, got %d", rec.Code)
	}
}

// TestWrap_BrowserAuthPaths は BrowserAuth のパス（/login, /callback, /select）が
// 直接処理されることを検証する。
func TestWrap_BrowserAuthPaths(t *testing.T) {
	a, _ := setupAuth(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for browser auth paths")
	})

	// /login は IdP にリダイレクトする
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	a.Wrap(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("/login: expected 302, got %d", rec.Code)
	}

	// /callback はパラメータ不足でエラーになるが、next は呼ばれない
	req = httptest.NewRequest(http.MethodGet, "/callback", nil)
	rec = httptest.NewRecorder()
	a.Wrap(next).ServeHTTP(rec, req)
	// code パラメータなしなので 400
	if rec.Code != http.StatusBadRequest {
		t.Errorf("/callback: expected 400, got %d", rec.Code)
	}

	// /select は単一プロバイダーなので /login にリダイレクト
	req = httptest.NewRequest(http.MethodGet, "/select", nil)
	rec = httptest.NewRecorder()
	a.Wrap(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("/select: expected 302, got %d", rec.Code)
	}
}

// TestWrap_SessionCookie_InvalidCookie は無効な Cookie 値の場合に
// ブラウザリクエストならリダイレクト、API リクエストなら 401 を返すことを検証する。
func TestWrap_SessionCookie_InvalidCookie(t *testing.T) {
	a, _ := setupAuth(t)

	t.Run("browser request with invalid cookie redirects", func(t *testing.T) {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("next should not be called")
		})

		req := httptest.NewRequest(http.MethodGet, "/page", nil)
		req.Header.Set("Accept", "text/html")
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "invalid-value"})
		rec := httptest.NewRecorder()

		a.Wrap(next).ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Errorf("expected 302, got %d", rec.Code)
		}
	})

	t.Run("API request with invalid cookie returns 401", func(t *testing.T) {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("next should not be called")
		})

		req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
		req.Header.Set("Accept", "application/json")
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "invalid-value"})
		rec := httptest.NewRecorder()

		a.Wrap(next).ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rec.Code)
		}
	})
}

// TestWrap_PassesRequestUnmodified は認証済みリクエストのパスやメソッドが
// next ハンドラーにそのまま渡されることを検証する。
func TestWrap_PassesRequestUnmodified(t *testing.T) {
	a, _ := setupAuth(t)

	ctx := context.Background()
	user := &User{Email: "test@example.com", Subject: "sub-1"}
	sess, _ := a.sessionManager.IssueSession(ctx, user, "https://example.com", "tok")
	cookieRec := httptest.NewRecorder()
	_ = a.sessionManager.SetCookie(cookieRec, sess.ID)
	cookieHeader := cookieRec.Header().Get("Set-Cookie")

	var gotPath, gotMethod string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/resource?foo=bar", nil)
	req.Header.Set("Cookie", cookieHeader)
	rec := httptest.NewRecorder()

	a.Wrap(next).ServeHTTP(rec, req)

	if gotPath != "/api/v1/resource" {
		t.Errorf("expected path /api/v1/resource, got %q", gotPath)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("expected method POST, got %q", gotMethod)
	}
}

// contains は strings.Contains のシンプルなラッパー。
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestWrap_OAuthASPaths_NonMatchingPaths は OAuth AS パスに一致しないパスが
// 通常のリクエスト判定ロジックを経由することを検証する。
func TestWrap_OAuthASPaths_NonMatchingPaths(t *testing.T) {
	a, _ := setupAuth(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called (no auth)")
	})

	// /.well-known/ だけど OAuth AS パスではないパス
	req := httptest.NewRequest(http.MethodGet, "/api/authorize", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	a.Wrap(next).ServeHTTP(rec, req)

	// OAuth AS パスではないので通常の判定（Accept: application/json → 401）
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for non-matching path, got %d", rec.Code)
	}
}

// TestWrap_SessionExpiredAt は ExpiresAt を過ぎたセッションが
// 認証されないことを検証する。
func TestWrap_SessionExpiredAt(t *testing.T) {
	a, _ := setupAuth(t)

	ctx := context.Background()
	user := &User{Email: "test@example.com", Subject: "sub-1"}

	// 期限切れセッションを直接作成
	sess := &Session{
		ID:             "expired-sess-id",
		User:           user,
		ProviderIssuer: "https://example.com",
		IDToken:        "token",
		CreatedAt:      time.Now().Add(-2 * time.Hour),
		ExpiresAt:      time.Now().Add(-1 * time.Hour),
	}
	_ = a.store.SetSession(ctx, sess.ID, sess, time.Hour)

	cookieRec := httptest.NewRecorder()
	_ = a.sessionManager.SetCookie(cookieRec, sess.ID)
	cookieHeader := cookieRec.Header().Get("Set-Cookie")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called for expired session")
	})

	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	req.Header.Set("Cookie", cookieHeader)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()

	a.Wrap(next).ServeHTTP(rec, req)

	// セッションは Store にあるが ExpiresAt を過ぎているのでリダイレクト
	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 for expired session, got %d", rec.Code)
	}
}
