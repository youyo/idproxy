package idproxy

import "context"

// contextKey はコンテキストキーの衝突を防ぐための unexported 型。
type contextKey struct{}

// userContextKey は User をコンテキストに保存するためのキー。
var userContextKey = contextKey{}

// User は認証済みユーザーの情報を保持する。
type User struct {
	// Email はユーザーのメールアドレス。
	Email string

	// Name はユーザーの表示名。
	Name string

	// Subject は OIDC sub クレーム。
	Subject string

	// Issuer は認証に使用された IdP の Issuer URL。
	Issuer string

	// Claims は ID Token の全クレーム。
	Claims map[string]interface{}
}

// UserFromContext はリクエストコンテキストから認証済みユーザー情報を取得する。
// 認証されていない場合は nil を返す。
func UserFromContext(ctx context.Context) *User {
	u, _ := ctx.Value(userContextKey).(*User)
	return u
}

// newContextWithUser は User をコンテキストに設定した新しいコンテキストを返す。
func newContextWithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, userContextKey, u)
}
