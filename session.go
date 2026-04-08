package idproxy

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
)

// sessionCookieName はセッション Cookie の名前。
const sessionCookieName = "_idproxy_session"

// SessionManager は Cookie ベースのセッション管理を担当する。
// gorilla/securecookie を使って Cookie を暗号化・署名し、
// Store インターフェース経由でセッションデータを永続化する。
type SessionManager struct {
	codec        securecookie.Codec
	store        Store
	maxAge       time.Duration
	secureCookie bool // Secure 属性: ExternalURL が https:// の場合 true
}

// NewSessionManager は新しい SessionManager を生成する。
// cfg.CookieSecret は 32 バイト以上が必要。
// cfg.Store が nil の場合はエラーを返す。
func NewSessionManager(cfg Config) (*SessionManager, error) {
	if len(cfg.CookieSecret) < 32 {
		return nil, fmt.Errorf("idproxy: cookie_secret must be at least 32 bytes, got %d", len(cfg.CookieSecret))
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("idproxy: store must not be nil")
	}

	// hashKey: HMAC 署名用（CookieSecret をそのまま使用）
	hashKey := cfg.CookieSecret

	// encryptionKey: AES-256 暗号化用（SHA-256 で CookieSecret を 32 バイトに派生）
	// トレードオフ: 同一ソースから派生させるため、CookieSecret 漏洩時は両方が危険にさらされる。
	// 一方で設定がシンプル（キー1本で運用可能）。将来的に HKDF 派生へ移行予定。
	encKeyRaw := sha256.Sum256(cfg.CookieSecret)
	encryptionKey := encKeyRaw[:]

	codec := securecookie.New(hashKey, encryptionKey)

	maxAge := cfg.SessionMaxAge
	if maxAge == 0 {
		maxAge = 24 * time.Hour
	}

	return &SessionManager{
		codec:        codec,
		store:        cfg.Store,
		maxAge:       maxAge,
		secureCookie: strings.HasPrefix(cfg.ExternalURL, "https://"),
	}, nil
}

// IssueSession は新しいセッションを発行し、Store に保存して返す。
// セッション ID は UUID v4 で生成する。
func (sm *SessionManager) IssueSession(ctx context.Context, user *User, providerIssuer, idToken string) (*Session, error) {
	id := uuid.New().String()
	now := time.Now()
	sess := &Session{
		ID:             id,
		User:           user,
		ProviderIssuer: providerIssuer,
		IDToken:        idToken,
		CreatedAt:      now,
		ExpiresAt:      now.Add(sm.maxAge),
	}
	if err := sm.store.SetSession(ctx, id, sess, sm.maxAge); err != nil {
		return nil, fmt.Errorf("idproxy: failed to store session: %w", err)
	}
	return sess, nil
}

// SetCookie はセッション ID を暗号化して Set-Cookie ヘッダーを設定する。
func (sm *SessionManager) SetCookie(w http.ResponseWriter, sessionID string) error {
	encoded, err := sm.codec.Encode(sessionCookieName, sessionID)
	if err != nil {
		return fmt.Errorf("idproxy: failed to encode session cookie: %w", err)
	}
	http.SetCookie(w, sm.newCookie(encoded, int(sm.maxAge.Seconds())))
	return nil
}

// GetSessionFromRequest はリクエストの Cookie からセッションを取得する。
// Cookie が存在しない場合は nil, nil を返す（エラーではない）。
// Cookie が無効（改ざん等）の場合は nil, error を返す。
// Store にセッションが存在しない（期限切れを含む）場合は nil, nil を返す。
func (sm *SessionManager) GetSessionFromRequest(ctx context.Context, r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		// http.ErrNoCookie を含む全エラーを「Cookie なし」として扱う
		return nil, nil
	}

	var sessionID string
	if err := sm.codec.Decode(sessionCookieName, cookie.Value, &sessionID); err != nil {
		return nil, fmt.Errorf("idproxy: invalid session cookie: %w", err)
	}

	sess, err := sm.store.GetSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("idproxy: failed to get session from store: %w", err)
	}
	// sess が nil の場合は「セッション不存在または期限切れ」
	return sess, nil
}

// DeleteSession はセッションを削除し、Cookie を無効化する。
// Cookie が存在しない場合は何もしない（冪等）。
// Cookie の復号が失敗した場合でも、MaxAge=-1 の Cookie を必ず設定する。
func (sm *SessionManager) DeleteSession(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		// Cookie なし: 何もしない（冪等）
		return nil
	}

	// 復号を試みる（成功した場合のみ Store から削除）
	var sessionID string
	if decErr := sm.codec.Decode(sessionCookieName, cookie.Value, &sessionID); decErr == nil {
		// 復号成功: Store からセッションを削除
		if err := sm.store.DeleteSession(ctx, sessionID); err != nil {
			// Store 削除に失敗しても Cookie は無効化する
			_ = err
		}
	}
	// 復号失敗・成功どちらの場合も Cookie を即時失効させる
	http.SetCookie(w, sm.newCookie("", -1))
	return nil
}

// newCookie は sessionCookieName に対応するセキュリティ属性付き Cookie を生成する。
// maxAge に -1 を指定すると即時失効（MaxAge=-1）になる。
func (sm *SessionManager) newCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   sm.secureCookie,
		SameSite: http.SameSiteLaxMode,
	}
}
