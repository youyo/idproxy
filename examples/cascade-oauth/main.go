// Package main は idproxy の OnAuthenticated フックを使った
// カスケード OAuth パターンの最小サンプルです。
//
// シナリオ:
//
//  1. ユーザーがブラウザで /protected にアクセス
//  2. idproxy が OIDC（社内 IdP 等）で認証させる
//  3. 認証完了直後、OnAuthenticated フックが「外部 OAuth トークン（例: Slack/Backlog）」
//     の有無を確認し、未接続なら /oauth/external/start にリダイレクト
//  4. 外部 OAuth フロー完了後、ユーザーは元の URL に戻る
//
// 実用上は外部 token の保存先（Store 共有 vs 別 backend）、refresh、
// lifecycle 不一致など多くの論点がありますが、本サンプルは「OnAuthenticated 経由で
// 外部接続状態をチェック → 未接続ならリダイレクト」という一ピースのみを示します。
// より詳細な責務分割・state 管理・refresh は docs/cascade-oauth-pattern.md 参照。
//
// 環境変数:
//
//	EXTERNAL_URL       - 外部公開 URL（必須、例: https://app.example.com）
//	COOKIE_SECRET      - Cookie 暗号化キー、hex エンコード 32 バイト以上（必須）
//	OIDC_ISSUER        - OIDC Issuer URL（必須）
//	OIDC_CLIENT_ID     - OAuth Client ID（必須）
//	OIDC_CLIENT_SECRET - OAuth Client Secret（オプション）
//	PORT               - リッスンポート（デフォルト: 8080）
package main

import (
	"context"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"sync"

	idproxy "github.com/youyo/idproxy"
	"github.com/youyo/idproxy/store"
)

// externalTokenStore は本サンプルでは in-memory map で代替。
// 本番では Store 実装に DynamoDB / Redis / SQLite を採用し、token を暗号化して保存する。
type externalTokenStore struct {
	mu     sync.Mutex
	tokens map[string]string // user email → external OAuth token（簡略化）
}

func newExternalTokenStore() *externalTokenStore {
	return &externalTokenStore{tokens: map[string]string{}}
}

func (s *externalTokenStore) HasToken(email string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.tokens[email]
	return ok
}

func main() {
	externalURL := mustEnv("EXTERNAL_URL")
	cookieSecretHex := mustEnv("COOKIE_SECRET")
	oidcIssuer := mustEnv("OIDC_ISSUER")
	oidcClientID := mustEnv("OIDC_CLIENT_ID")
	oidcClientSecret := os.Getenv("OIDC_CLIENT_SECRET")

	cookieSecret, err := hex.DecodeString(cookieSecretHex)
	if err != nil {
		log.Fatalf("COOKIE_SECRET: invalid hex: %v", err)
	}

	tokenStore := newExternalTokenStore()

	cfg := idproxy.Config{
		Providers: []idproxy.OIDCProvider{
			{
				Issuer:       oidcIssuer,
				ClientID:     oidcClientID,
				ClientSecret: oidcClientSecret,
			},
		},
		ExternalURL:  externalURL,
		CookieSecret: cookieSecret,
		Store:        store.NewMemoryStore(),

		// 認証完了後のデフォルト遷移先。OIDC 認証成功直後、外部 OAuth 接続
		// 確認のため /oauth/external/start へ飛ばすシナリオを想定する。
		DefaultPostLoginPath: "/protected",

		// 認証完了時のフック。
		//   - 外部 OAuth 未接続なら /oauth/external/start にリダイレクト
		//   - 接続済みなら元のリダイレクト先（state.RedirectURI もしくは DefaultPostLoginPath）に任せる
		// 認証完了時のフック。
		// 注意: このフックは「OIDC 認証完了直後の初回リダイレクト先変更」にのみ使用します。
		// フック実行時点でセッション Cookie は既に発行済みのため、/protected などの保護
		// エンドポイントへのアクセス制御には引き続き per-request チェック（下記 /protected
		// ハンドラを参照）が必要です。OnAuthenticated を per-request middleware の代替として
		// 使うことはできません。
		OnAuthenticated: func(w http.ResponseWriter, r *http.Request, user *idproxy.User) (redirectTo string, handled bool) {
			if !tokenStore.HasToken(user.Email) {
				log.Printf("OnAuthenticated: user %q has no external token; redirecting to /oauth/external/start",
					user.Email)
				// `handled=false, redirectTo!=""` → BrowserAuth が Validator を通してから 302
				// 注意: /callback リクエストには redirect_to クエリは含まれないため、
				// ここでは固定パスを返す。元の destination が必要な場合は Store を
				// 経由して stateData.RedirectURI を引き継ぐ設計が必要（docs/cascade-oauth-pattern.md 参照）。
				return "/oauth/external/start", false
			}
			log.Printf("OnAuthenticated: user %q has external token; using default redirect", user.Email)
			return "", false
		},

		// 同一 origin 安全のため Strict Validator を opt-in する。
		// （DefaultPostLoginPath や OnAuthenticated の戻り値も自動でこの Validator に通される）
	}
	cfg.UseStrictPostLoginRedirectValidator()

	auth, err := idproxy.New(context.Background(), cfg)
	if err != nil {
		log.Fatalf("idproxy.New: %v", err)
	}

	mux := http.NewServeMux()

	// 認証必須エンドポイント（idproxy.Auth.Wrap でラップ）
	// idproxy セッション（OIDC 認証済み）に加え、外部 OAuth トークンも必須とする。
	// OnAuthenticated フックはリダイレクト先変更のみ担当し、ここでのアクセス制御は
	// 代替しない。セッション有効 + 外部トークンなしでも /protected に到達できるため、
	// per-request チェックが必要。
	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		user := idproxy.UserFromContext(r.Context())
		if user == nil {
			http.Error(w, "no user in context", http.StatusInternalServerError)
			return
		}
		// 外部 OAuth トークン必須チェック（per-request）
		if !tokenStore.HasToken(user.Email) {
			http.Redirect(w, r, "/oauth/external/start", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("welcome, " + user.Email))
	})

	// 外部 OAuth フロー（本サンプルでは「即座にトークン取得した」と仮定する dummy）
	mux.HandleFunc("/oauth/external/start", func(w http.ResponseWriter, r *http.Request) {
		user := idproxy.UserFromContext(r.Context())
		if user == nil {
			http.Error(w, "no user in context", http.StatusInternalServerError)
			return
		}
		// 本番では外部 IdP（Slack/Backlog/kintone）に authorize リダイレクト → /oauth/external/callback で交換
		tokenStore.mu.Lock()
		tokenStore.tokens[user.Email] = "external-token-stub"
		tokenStore.mu.Unlock()

		returnTo := r.URL.Query().Get("return_to")
		if returnTo == "" {
			returnTo = "/protected"
		}
		// return_to を Validator で検証してからリダイレクト（オープンリダイレクト防止）
		if validate := cfg.PostLoginRedirectValidator; validate != nil {
			if err := validate(returnTo); err != nil {
				http.Error(w, "invalid return_to", http.StatusBadRequest)
				return
			}
		}
		http.Redirect(w, r, returnTo, http.StatusFound)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("listening on :%s (external_url=%s)", port, externalURL)
	if err := http.ListenAndServe(":"+port, auth.Wrap(mux)); err != nil { //nolint:gosec
		log.Fatal(err)
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("%s is required", key)
	}
	return v
}
