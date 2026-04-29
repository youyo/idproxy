// Package sqlite は idproxy.Store の SQLite 実装を提供する。
//
// 用途: 単一ノードでのファイルベース永続化。modernc.org/sqlite を使用するため CGO 不要。
//
// 使い方:
//
//	s, err := sqlite.New("/var/lib/idproxy/state.db")
//	if err != nil { ... }
//	defer s.Close()
//	cfg.Store = s
//
// メモリ上で動かしたい場合は ":memory:" を渡す（テスト用途）。
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/youyo/idproxy"

	_ "modernc.org/sqlite" // sqlite ドライバ登録
)

const (
	defaultCleanupInterval = 5 * time.Minute
	driverName             = "sqlite"
)

// schema は初期化時に一括実行する DDL。
const schema = `
CREATE TABLE IF NOT EXISTS sessions (
    key TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS auth_codes (
    key TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_codes_expires_at ON auth_codes(expires_at);

CREATE TABLE IF NOT EXISTS access_tokens (
    key TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_at ON access_tokens(expires_at);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    key TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

CREATE TABLE IF NOT EXISTS family_revocations (
    key TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_family_revocations_expires_at ON family_revocations(expires_at);

CREATE TABLE IF NOT EXISTS clients (
    key TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
`

// コンパイル時にインターフェース実装を保証する。
var _ idproxy.Store = (*Store)(nil)

// Store は SQLite ベースの idproxy.Store 実装。
type Store struct {
	db        *sql.DB
	stopCh    chan struct{}
	closeOnce sync.Once
	closed    bool
	closeMu   sync.Mutex
}

// New は指定したパスで SQLite データベースを開き、スキーマを適用する。
// path に ":memory:" を指定するとメモリ上で動作する（テスト用途）。
func New(path string) (*Store, error) {
	return NewWithCleanupInterval(path, defaultCleanupInterval)
}

// NewWithCleanupInterval は cleanup ゴルーチンの周期を指定して Store を生成する。
// interval <= 0 の場合は cleanup ゴルーチンを起動しない（テスト用途）。
func NewWithCleanupInterval(path string, interval time.Duration) (*Store, error) {
	// _txlock=immediate: database/sql の BeginTx が "BEGIN IMMEDIATE" を発行するようにする。
	// ConsumeRefreshToken の CAS では SELECT → UPDATE の順で操作するため、deferred BEGIN だと
	// SELECT 時点では shared lock しか取れず、UPDATE で初めて write lock を取りに行くタイミングで
	// 並行トランザクションと SQLITE_BUSY を起こしうる。immediate にすると BEGIN 時点で
	// reserved lock を取得し、レース全体を直列化できる。
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)&_txlock=immediate"
	if path == ":memory:" {
		// :memory: では WAL が使えないため pragma を絞る
		dsn = path + "?_pragma=busy_timeout(5000)&_txlock=immediate"
	}
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	// :memory: はコネクションごとに別 DB になるため単一接続に限定
	if path == ":memory:" {
		db.SetMaxOpenConns(1)
	}
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: apply schema: %w", err)
	}
	s := &Store{
		db:     db,
		stopCh: make(chan struct{}),
	}
	if interval > 0 {
		go s.cleanupLoop(interval)
	}
	return s, nil
}

func (s *Store) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = s.Cleanup(context.Background())
		case <-s.stopCh:
			return
		}
	}
}

func nowUnix() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

// --- Session ---

func (s *Store) SetSession(ctx context.Context, id string, sess *idproxy.Session, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("sqlite: marshal session: %w", err)
	}
	now := nowUnix()
	exp := now + ttl.Milliseconds()
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO sessions (key, data, expires_at, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            data=excluded.data, expires_at=excluded.expires_at, updated_at=excluded.updated_at`,
		id, string(b), exp, now)
	if err != nil {
		return fmt.Errorf("sqlite: set session: %w", err)
	}
	return nil
}

func (s *Store) GetSession(ctx context.Context, id string) (*idproxy.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var data string
	var exp int64
	err := s.db.QueryRowContext(ctx, `SELECT data, expires_at FROM sessions WHERE key=?`, id).Scan(&data, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: get session: %w", err)
	}
	if exp <= nowUnix() {
		return nil, nil
	}
	var sess idproxy.Session
	if err := json.Unmarshal([]byte(data), &sess); err != nil {
		return nil, fmt.Errorf("sqlite: unmarshal session: %w", err)
	}
	return &sess, nil
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE key=?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete session: %w", err)
	}
	return nil
}

// --- AuthCode ---

func (s *Store) SetAuthCode(ctx context.Context, code string, data *idproxy.AuthCodeData, ttl time.Duration) error {
	return setJSON(ctx, s.db, "auth_codes", code, data, ttl)
}

func (s *Store) GetAuthCode(ctx context.Context, code string) (*idproxy.AuthCodeData, error) {
	var v idproxy.AuthCodeData
	ok, err := getJSON(ctx, s.db, "auth_codes", code, &v)
	if err != nil || !ok {
		return nil, err
	}
	return &v, nil
}

func (s *Store) DeleteAuthCode(ctx context.Context, code string) error {
	return deleteRow(ctx, s.db, "auth_codes", code)
}

// --- AccessToken ---

func (s *Store) SetAccessToken(ctx context.Context, jti string, data *idproxy.AccessTokenData, ttl time.Duration) error {
	return setJSON(ctx, s.db, "access_tokens", jti, data, ttl)
}

func (s *Store) GetAccessToken(ctx context.Context, jti string) (*idproxy.AccessTokenData, error) {
	var v idproxy.AccessTokenData
	ok, err := getJSON(ctx, s.db, "access_tokens", jti, &v)
	if err != nil || !ok {
		return nil, err
	}
	return &v, nil
}

func (s *Store) DeleteAccessToken(ctx context.Context, jti string) error {
	return deleteRow(ctx, s.db, "access_tokens", jti)
}

// --- Client ---

func (s *Store) SetClient(ctx context.Context, clientID string, data *idproxy.ClientData) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("sqlite: marshal client: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO clients (key, data, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at`,
		clientID, string(b), nowUnix())
	if err != nil {
		return fmt.Errorf("sqlite: set client: %w", err)
	}
	return nil
}

func (s *Store) GetClient(ctx context.Context, clientID string) (*idproxy.ClientData, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var data string
	err := s.db.QueryRowContext(ctx, `SELECT data FROM clients WHERE key=?`, clientID).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: get client: %w", err)
	}
	var c idproxy.ClientData
	if err := json.Unmarshal([]byte(data), &c); err != nil {
		return nil, fmt.Errorf("sqlite: unmarshal client: %w", err)
	}
	return &c, nil
}

func (s *Store) DeleteClient(ctx context.Context, clientID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM clients WHERE key=?`, clientID)
	if err != nil {
		return fmt.Errorf("sqlite: delete client: %w", err)
	}
	return nil
}

// --- RefreshToken ---

func (s *Store) SetRefreshToken(ctx context.Context, id string, data *idproxy.RefreshTokenData, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("sqlite: marshal refresh token: %w", err)
	}
	now := nowUnix()
	exp := now + ttl.Milliseconds()
	used := 0
	if data.Used {
		used = 1
	}
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO refresh_tokens (key, data, used, expires_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            data=excluded.data, used=excluded.used,
            expires_at=excluded.expires_at, updated_at=excluded.updated_at`,
		id, string(b), used, exp, now)
	if err != nil {
		return fmt.Errorf("sqlite: set refresh token: %w", err)
	}
	return nil
}

func (s *Store) GetRefreshToken(ctx context.Context, id string) (*idproxy.RefreshTokenData, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var data string
	var exp int64
	err := s.db.QueryRowContext(ctx,
		`SELECT data, expires_at FROM refresh_tokens WHERE key=?`, id).Scan(&data, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: get refresh token: %w", err)
	}
	if exp <= nowUnix() {
		return nil, nil
	}
	var v idproxy.RefreshTokenData
	if err := json.Unmarshal([]byte(data), &v); err != nil {
		return nil, fmt.Errorf("sqlite: unmarshal refresh token: %w", err)
	}
	return &v, nil
}

// ConsumeRefreshToken はトランザクション内で「used=0 を 1 に CAS」を実現する。
// SQLite は SERIALIZABLE 相当なので BEGIN IMMEDIATE で write lock を取得することで
// 並行 ConsumeRefreshToken の race を防ぐ。
func (s *Store) ConsumeRefreshToken(ctx context.Context, id string) (*idproxy.RefreshTokenData, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	for {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("sqlite: begin: %w", err)
		}

		var data string
		var used int
		var exp int64
		err = tx.QueryRowContext(ctx,
			`SELECT data, used, expires_at FROM refresh_tokens WHERE key=?`, id).Scan(&data, &used, &exp)
		if errors.Is(err, sql.ErrNoRows) {
			_ = tx.Rollback()
			return nil, nil
		}
		if err != nil {
			_ = tx.Rollback()
			return nil, fmt.Errorf("sqlite: consume select: %w", err)
		}
		if exp <= nowUnix() {
			_ = tx.Rollback()
			return nil, nil
		}

		var v idproxy.RefreshTokenData
		if err := json.Unmarshal([]byte(data), &v); err != nil {
			_ = tx.Rollback()
			return nil, fmt.Errorf("sqlite: unmarshal refresh token: %w", err)
		}

		if used == 1 {
			_ = tx.Rollback()
			v.Used = true
			return &v, idproxy.ErrRefreshTokenAlreadyConsumed
		}

		// CAS: used=0 → 1
		v.Used = true
		newData, err := json.Marshal(&v)
		if err != nil {
			_ = tx.Rollback()
			return nil, fmt.Errorf("sqlite: marshal: %w", err)
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE refresh_tokens SET data=?, used=1, updated_at=? WHERE key=? AND used=0`,
			string(newData), nowUnix(), id)
		if err != nil {
			_ = tx.Rollback()
			if isBusy(err) {
				continue
			}
			return nil, fmt.Errorf("sqlite: consume update: %w", err)
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			// 並行更新で先を越された → リトライして used=1 経路へ
			_ = tx.Rollback()
			continue
		}
		if err := tx.Commit(); err != nil {
			// Commit 失敗時 database/sql は内部で finalize するが、念のため
			// 明示的に Rollback してリソース解放を確実化する（ErrTxDone は無視）。
			_ = tx.Rollback()
			if isBusy(err) {
				continue
			}
			return nil, fmt.Errorf("sqlite: commit: %w", err)
		}
		return &v, nil
	}
}

func isBusy(err error) bool {
	if err == nil {
		return false
	}
	// modernc.org/sqlite の Error.Code() を使うのが理想だが、
	// 文字列比較で十分（busy / locked のみ）。
	msg := err.Error()
	return strings.Contains(msg, "SQLITE_BUSY") || strings.Contains(msg, "database is locked")
}

// --- FamilyRevocation ---

func (s *Store) SetFamilyRevocation(ctx context.Context, familyID string, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := nowUnix()
	exp := now + ttl.Milliseconds()
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO family_revocations (key, expires_at, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET expires_at=excluded.expires_at, updated_at=excluded.updated_at`,
		familyID, exp, now)
	if err != nil {
		return fmt.Errorf("sqlite: set family revocation: %w", err)
	}
	return nil
}

func (s *Store) IsFamilyRevoked(ctx context.Context, familyID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	var exp int64
	err := s.db.QueryRowContext(ctx,
		`SELECT expires_at FROM family_revocations WHERE key=?`, familyID).Scan(&exp)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sqlite: is family revoked: %w", err)
	}
	if exp <= nowUnix() {
		return false, nil
	}
	return true, nil
}

// --- Cleanup / Close ---

func (s *Store) Cleanup(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := nowUnix()
	// テーブル名は固定の定数 SQL 5 本に展開する。動的連結を避けることで
	// 静的解析（CWE-89）を満たし、誤って外部入力を渡す回帰も防ぐ。
	stmts := []string{
		`DELETE FROM sessions WHERE expires_at <= ?`,
		`DELETE FROM auth_codes WHERE expires_at <= ?`,
		`DELETE FROM access_tokens WHERE expires_at <= ?`,
		`DELETE FROM refresh_tokens WHERE expires_at <= ?`,
		`DELETE FROM family_revocations WHERE expires_at <= ?`,
	}
	for _, q := range stmts {
		if _, err := s.db.ExecContext(ctx, q, now); err != nil {
			return fmt.Errorf("sqlite: cleanup: %w", err)
		}
	}
	return nil
}

func (s *Store) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.closeOnce.Do(func() {
		close(s.stopCh)
	})
	return s.db.Close()
}

// --- 内部ヘルパー ---

// dbExecutor は *sql.DB と *sql.Tx を抽象化する最小インターフェース。
type dbExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func setJSON(ctx context.Context, db dbExecutor, table, key string, v any, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("sqlite: marshal %s: %w", table, err)
	}
	now := nowUnix()
	exp := now + ttl.Milliseconds()
	q := "INSERT INTO " + table + " (key, data, expires_at, updated_at) VALUES (?, ?, ?, ?)" +
		" ON CONFLICT(key) DO UPDATE SET data=excluded.data, expires_at=excluded.expires_at, updated_at=excluded.updated_at"
	if _, err := db.ExecContext(ctx, q, key, string(b), exp, now); err != nil {
		return fmt.Errorf("sqlite: set %s: %w", table, err)
	}
	return nil
}

func getJSON(ctx context.Context, db dbExecutor, table, key string, dst any) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	var data string
	var exp int64
	err := db.QueryRowContext(ctx, "SELECT data, expires_at FROM "+table+" WHERE key=?", key).Scan(&data, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sqlite: get %s: %w", table, err)
	}
	if exp <= nowUnix() {
		return false, nil
	}
	if err := json.Unmarshal([]byte(data), dst); err != nil {
		return false, fmt.Errorf("sqlite: unmarshal %s: %w", table, err)
	}
	return true, nil
}

func deleteRow(ctx context.Context, db dbExecutor, table, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM "+table+" WHERE key=?", key); err != nil {
		return fmt.Errorf("sqlite: delete %s: %w", table, err)
	}
	return nil
}
