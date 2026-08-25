package idproxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

// identityHeaderDenylist は upstream へ転送する前に必ず除去するヘッダー名の一覧。
//
// oauth2-proxy 系の慣習では upstream がこれらを「認証済みユーザーの身元」として
// 信頼するため、クライアントが送ってきた値をそのまま通すと upstream に対する
// 認証バイパスになる。idproxy 自身が設定する分だけを通す。
var identityHeaderDenylist = []string{
	"X-Forwarded-User",
	"X-Forwarded-Email",
	"X-Forwarded-Preferred-Username",
	"X-Forwarded-Groups",
	"X-Forwarded-Access-Token",
	"X-Forwarded-Id-Token",
	"X-Auth-Request-User",
	"X-Auth-Request-Email",
	"X-Auth-Request-Preferred-Username",
	"X-Auth-Request-Groups",
	"X-Auth-Request-Access-Token",
	"X-Auth-Request-Redirect",
	"X-Remote-User",
	"X-Remote-Email",
	"X-Remote-Groups",
	"X-Authenticated-User",
	"X-User",
	"X-Email",
}

// NewReverseProxy は target への安全なリバースプロキシを生成する。
// `Auth.Wrap` の下流ハンドラーとして使うことを想定している。
//
// `httputil.NewSingleHostReverseProxy` との違い:
//   - クライアント由来の身元ヘッダー（identityHeaderDenylist）を必ず除去する。
//   - `X-Forwarded-For` をクライアントの値に追記せず、実接続元で置き換える。
//   - Host ヘッダーを target のものに揃える。
//   - `UserFromContext` で認証済みユーザーが取れる場合、
//     `X-Forwarded-User` / `X-Forwarded-Email` / `X-Forwarded-Preferred-Username`
//     を idproxy が検証した値で設定する。未認証なら一切設定しない。
//
// SSE / Streamable HTTP を透過させるため `FlushInterval` に -1 を設定する。
func NewReverseProxy(target *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// クライアントが詐称した身元ヘッダーを除去（Del は正規化して削除する）
			for _, name := range identityHeaderDenylist {
				pr.Out.Header.Del(name)
			}

			// SetXForwarded は既存値に追記するため、先に落としてから呼ぶ。
			// これによりクライアントが前置した偽の IP は upstream に届かない。
			pr.Out.Header.Del("X-Forwarded-For")
			pr.SetXForwarded()

			// SetURL は Host も target のものに揃える。
			pr.SetURL(target)

			// idproxy が検証した身元だけを upstream に渡す。
			if user := UserFromContext(pr.In.Context()); user != nil {
				setIfNotEmpty(pr.Out.Header, "X-Forwarded-User", user.Subject)
				setIfNotEmpty(pr.Out.Header, "X-Forwarded-Email", user.Email)
				setIfNotEmpty(pr.Out.Header, "X-Forwarded-Preferred-Username", user.Name)
			}
		},
		FlushInterval: -1,
	}
}

// setIfNotEmpty は value が空でない場合のみヘッダーを設定する。
func setIfNotEmpty(h http.Header, name, value string) {
	if value != "" {
		h.Set(name, value)
	}
}
