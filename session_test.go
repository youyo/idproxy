package idproxy

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- テスト用インメモリ Store ---

// testMemoryStore は session_test.go 専用のシンプルな Store 実装。
// store.MemoryStore は循環インポートになるため使用できない。
type testMemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func newTestMemoryStore() *testMemoryStore {
	return &testMemoryStore{sessions: make(map[string]*Session)}
}

func (s *testMemoryStore) SetSession(_ context.Context, id string, session *Session, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = session
	return nil
}

func (s *testMemoryStore) GetSession(_ context.Context, id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, nil
	}
	return sess, nil
}

func (s *testMemoryStore) DeleteSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}

func (s *testMemoryStore) SetAuthCode(_ context.Context, _ string, _ *AuthCodeData, _ time.Duration) error {
	return nil
}
func (s *testMemoryStore) GetAuthCode(_ context.Context, _ string) (*AuthCodeData, error) {
	return nil, nil
}
func (s *testMemoryStore) DeleteAuthCode(_ context.Context, _ string) error { return nil }
func (s *testMemoryStore) SetAccessToken(_ context.Context, _ string, _ *AccessTokenData, _ time.Duration) error {
	return nil
}
func (s *testMemoryStore) GetAccessToken(_ context.Context, _ string) (*AccessTokenData, error) {
	return nil, nil
}
func (s *testMemoryStore) DeleteAccessToken(_ context.Context, _ string) error { return nil }
func (s *testMemoryStore) Cleanup(_ context.Context) error                      { return nil }
func (s *testMemoryStore) Close() error                                         { return nil }

// --- ヘルパー関数 ---

// newTestConfig は SessionManager テスト用の最小 Config を返す。
func newTestConfig(t *testing.T) (Config, *testMemoryStore) {
	t.Helper()
	s := newTestMemoryStore()
	cfg := Config{
		CookieSecret:  bytes.Repeat([]byte("a"), 32),
		ExternalURL:   "https://example.com",
		SessionMaxAge: time.Hour,
		Providers: []OIDCProvider{
			{Issuer: "https://example.com", ClientID: "x", ClientSecret: "y"},
		},
		Store: s,
	}
	return cfg, s
}

// newTestSessionManager はテスト用 SessionManager と testMemoryStore を返す。
func newTestSessionManager(t *testing.T) (*SessionManager, *testMemoryStore) {
	t.Helper()
	cfg, s := newTestConfig(t)
	sm, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	return sm, s
}

// newTestUser はテスト用 User を返す。
func newTestUser() *User {
	return &User{
		Email:   "test@example.com",
		Name:    "Test User",
		Subject: "sub-123",
		Issuer:  "https://example.com",
	}
}

// requestWithCookies は指定した Cookie を持つ *http.Request を返す。
func requestWithCookies(cookies []*http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return r
}

// --- T01: NewSessionManager_正常 ---

func TestNewSessionManager_Valid(t *testing.T) {
	cfg, _ := newTestConfig(t)
	sm, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("want nil error, got %v", err)
	}
	if sm == nil {
		t.Fatal("want non-nil SessionManager")
	}
}

// --- T07: NewSessionManager_CookieSecret 短すぎ ---

func TestNewSessionManager_ShortCookieSecret(t *testing.T) {
	cfg, _ := newTestConfig(t)
	cfg.CookieSecret = bytes.Repeat([]byte("a"), 16) // 16バイト = 短すぎ
	_, err := NewSessionManager(cfg)
	if err == nil {
		t.Fatal("want error for short cookie secret, got nil")
	}
}

// --- T02: IssueSession_セッション発行 ---

func TestIssueSession_CreatesSession(t *testing.T) {
	sm, s := newTestSessionManager(t)
	ctx := context.Background()
	user := newTestUser()

	sess, err := sm.IssueSession(ctx, user, "https://issuer.example.com", "raw-id-token")
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	if sess == nil {
		t.Fatal("want non-nil Session")
	}
	if sess.ID == "" {
		t.Error("want non-empty session ID")
	}
	if sess.User == nil || sess.User.Email != user.Email {
		t.Errorf("want user email %q, got %v", user.Email, sess.User)
	}
	if sess.ProviderIssuer != "https://issuer.example.com" {
		t.Errorf("want ProviderIssuer %q, got %q", "https://issuer.example.com", sess.ProviderIssuer)
	}
	if sess.IDToken != "raw-id-token" {
		t.Errorf("want IDToken %q, got %q", "raw-id-token", sess.IDToken)
	}

	// Store に保存されているか確認
	stored, err := s.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if stored == nil {
		t.Fatal("session not found in store after IssueSession")
	}
}

// --- T03: IssueSession_ExpiresAt確認 ---

func TestIssueSession_ExpiresAt(t *testing.T) {
	sm, _ := newTestSessionManager(t)
	ctx := context.Background()

	before := time.Now()
	sess, err := sm.IssueSession(ctx, newTestUser(), "https://issuer", "token")
	after := time.Now()

	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	wantMin := before.Add(time.Hour)
	wantMax := after.Add(time.Hour)

	if sess.ExpiresAt.Before(wantMin) || sess.ExpiresAt.After(wantMax) {
		t.Errorf("ExpiresAt %v out of range [%v, %v]", sess.ExpiresAt, wantMin, wantMax)
	}
}

// --- T12: IssueSession_IDはUUID v4形式 ---

func TestIssueSession_IDIsUUID(t *testing.T) {
	sm, _ := newTestSessionManager(t)
	ctx := context.Background()

	sess, err := sm.IssueSession(ctx, newTestUser(), "https://issuer", "token")
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	// UUID v4 は "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx" 形式（36文字）
	id := sess.ID
	if len(id) != 36 {
		t.Errorf("want UUID length 36, got %d: %q", len(id), id)
	}
	parts := strings.Split(id, "-")
	if len(parts) != 5 {
		t.Errorf("want 5 UUID parts, got %d: %q", len(parts), id)
	}
	// version=4 チェック: 3番目の部分の先頭が '4'
	if len(parts[2]) > 0 && parts[2][0] != '4' {
		t.Errorf("want UUID version 4, got %q in %q", parts[2], id)
	}
}

// --- T04: SetCookie_Cookie発行 ---

func TestSetCookie_SetsCookieHeader(t *testing.T) {
	sm, _ := newTestSessionManager(t)
	ctx := context.Background()

	sess, err := sm.IssueSession(ctx, newTestUser(), "https://issuer", "token")
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	w := httptest.NewRecorder()
	if err := sm.SetCookie(w, sess.ID); err != nil {
		t.Fatalf("SetCookie: %v", err)
	}

	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("want Set-Cookie header, got none")
	}
	found := false
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("want cookie %q, not found in %v", sessionCookieName, cookies)
	}
}

// --- T13: SetCookie_Secure属性確認 ---

func TestSetCookie_SecureAttribute(t *testing.T) {
	cfg, _ := newTestConfig(t)
	cfg.ExternalURL = "https://example.com"
	sm, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	ctx := context.Background()
	sess, err := sm.IssueSession(ctx, newTestUser(), "https://issuer", "token")
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	w := httptest.NewRecorder()
	if err := sm.SetCookie(w, sess.ID); err != nil {
		t.Fatalf("SetCookie: %v", err)
	}

	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName {
			if !c.Secure {
				t.Error("want Secure=true for https ExternalURL")
			}
			return
		}
	}
	t.Errorf("cookie %q not found", sessionCookieName)
}

// --- T14: SetCookie_HttpOnly属性確認 ---

func TestSetCookie_HttpOnlyAttribute(t *testing.T) {
	sm, _ := newTestSessionManager(t)
	ctx := context.Background()

	sess, err := sm.IssueSession(ctx, newTestUser(), "https://issuer", "token")
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	w := httptest.NewRecorder()
	if err := sm.SetCookie(w, sess.ID); err != nil {
		t.Fatalf("SetCookie: %v", err)
	}

	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName {
			if !c.HttpOnly {
				t.Error("want HttpOnly=true")
			}
			return
		}
	}
	t.Errorf("cookie %q not found", sessionCookieName)
}

// --- T15: SetCookie_SameSite=Lax確認 ---

func TestSetCookie_SameSiteLax(t *testing.T) {
	sm, _ := newTestSessionManager(t)
	ctx := context.Background()

	sess, err := sm.IssueSession(ctx, newTestUser(), "https://issuer", "token")
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	w := httptest.NewRecorder()
	if err := sm.SetCookie(w, sess.ID); err != nil {
		t.Fatalf("SetCookie: %v", err)
	}

	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName {
			if c.SameSite != http.SameSiteLaxMode {
				t.Errorf("want SameSite=Lax, got %v", c.SameSite)
			}
			return
		}
	}
	t.Errorf("cookie %q not found", sessionCookieName)
}

// --- T05: GetSessionFromRequest_正常 ---

func TestGetSessionFromRequest_Valid(t *testing.T) {
	sm, _ := newTestSessionManager(t)
	ctx := context.Background()
	user := newTestUser()

	sess, err := sm.IssueSession(ctx, user, "https://issuer", "token")
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	w := httptest.NewRecorder()
	if err := sm.SetCookie(w, sess.ID); err != nil {
		t.Fatalf("SetCookie: %v", err)
	}

	r := requestWithCookies(w.Result().Cookies())
	got, err := sm.GetSessionFromRequest(ctx, r)
	if err != nil {
		t.Fatalf("GetSessionFromRequest: %v", err)
	}
	if got == nil {
		t.Fatal("want non-nil session, got nil")
	}
	if got.ID != sess.ID {
		t.Errorf("want session ID %q, got %q", sess.ID, got.ID)
	}
	if got.User == nil || got.User.Email != user.Email {
		t.Errorf("want user email %q, got %v", user.Email, got.User)
	}
}

// --- T08: GetSessionFromRequest_Cookie無し ---

func TestGetSessionFromRequest_NoCookie(t *testing.T) {
	sm, _ := newTestSessionManager(t)
	ctx := context.Background()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	got, err := sm.GetSessionFromRequest(ctx, r)
	if err != nil {
		t.Fatalf("want nil error for no cookie, got %v", err)
	}
	if got != nil {
		t.Fatalf("want nil session for no cookie, got %v", got)
	}
}

// --- T09: GetSessionFromRequest_Cookie改ざん ---

func TestGetSessionFromRequest_TamperedCookie(t *testing.T) {
	sm, _ := newTestSessionManager(t)
	ctx := context.Background()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: "this-is-not-a-valid-encrypted-value",
	})

	got, err := sm.GetSessionFromRequest(ctx, r)
	if err == nil {
		t.Fatal("want error for tampered cookie, got nil")
	}
	if got != nil {
		t.Fatalf("want nil session for tampered cookie, got %v", got)
	}
}

// --- T10: GetSessionFromRequest_Store期限切れ（決定論的: Store.DeleteSession で削除） ---

func TestGetSessionFromRequest_StoreSessionDeleted(t *testing.T) {
	sm, s := newTestSessionManager(t)
	ctx := context.Background()

	// セッションを発行
	sess, err := sm.IssueSession(ctx, newTestUser(), "https://issuer", "token")
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	// Store から直接削除（決定論的に「存在しない」状態を作る）
	if err := s.DeleteSession(ctx, sess.ID); err != nil {
		t.Fatalf("Store.DeleteSession: %v", err)
	}

	// Cookie は有効だが Store にセッションが存在しない
	w := httptest.NewRecorder()
	if err := sm.SetCookie(w, sess.ID); err != nil {
		t.Fatalf("SetCookie: %v", err)
	}

	r := requestWithCookies(w.Result().Cookies())
	got, err := sm.GetSessionFromRequest(ctx, r)
	if err != nil {
		t.Fatalf("want nil error when session not in store, got %v", err)
	}
	if got != nil {
		t.Fatalf("want nil session when not in store, got %v", got)
	}
}

// --- T06: DeleteSession_削除 ---

func TestDeleteSession_DeletesSessionAndCookie(t *testing.T) {
	sm, s := newTestSessionManager(t)
	ctx := context.Background()

	// セッション発行
	sess, err := sm.IssueSession(ctx, newTestUser(), "https://issuer", "token")
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	// Cookie を持つリクエストを作成
	w1 := httptest.NewRecorder()
	if err := sm.SetCookie(w1, sess.ID); err != nil {
		t.Fatalf("SetCookie: %v", err)
	}
	r := requestWithCookies(w1.Result().Cookies())

	// DeleteSession を呼ぶ
	w2 := httptest.NewRecorder()
	if err := sm.DeleteSession(ctx, w2, r); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	// Store にセッションが残っていないか確認
	stored, err := s.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession after delete: %v", err)
	}
	if stored != nil {
		t.Error("want session deleted from store, but still exists")
	}

	// Set-Cookie ヘッダーに MaxAge=-1 が含まれるか確認
	found := false
	for _, c := range w2.Result().Cookies() {
		if c.Name == sessionCookieName {
			if c.MaxAge != -1 {
				t.Errorf("want MaxAge=-1 for deleted cookie, got %d", c.MaxAge)
			}
			found = true
			break
		}
	}
	if !found {
		t.Errorf("want Set-Cookie %q with MaxAge=-1, not found", sessionCookieName)
	}
}

// --- DeleteSession_Cookie無し（冪等） ---

func TestDeleteSession_NoCookie_Idempotent(t *testing.T) {
	sm, _ := newTestSessionManager(t)
	ctx := context.Background()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	// Cookie がなくてもエラーにならない
	if err := sm.DeleteSession(ctx, w, r); err != nil {
		t.Fatalf("want nil error for no cookie, got %v", err)
	}
}

// --- DeleteSession_Cookie改ざん時もCookieを無効化 ---

func TestDeleteSession_TamperedCookie_StillClearsCookie(t *testing.T) {
	sm, _ := newTestSessionManager(t)
	ctx := context.Background()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: "invalid-tampered-value",
	})

	w := httptest.NewRecorder()
	// 復号失敗でもエラーを返さず、Cookie は MaxAge=-1 で無効化する
	if err := sm.DeleteSession(ctx, w, r); err != nil {
		t.Fatalf("want nil error even on tampered cookie, got %v", err)
	}

	// MaxAge=-1 の Cookie が Set-Cookie されているか確認
	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName {
			if c.MaxAge != -1 {
				t.Errorf("want MaxAge=-1, got %d", c.MaxAge)
			}
			found = true
			break
		}
	}
	if !found {
		t.Errorf("want Set-Cookie %q with MaxAge=-1 even on tampered cookie", sessionCookieName)
	}
}
