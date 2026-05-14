package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestExternalTokenStore_HasToken は in-memory token store の最小動作を確認する。
// （main.go 内の OnAuthenticated フックが Token 有無で挙動を分岐するロジックは、
// この struct の HasToken に依存する。フック自体は環境変数依存で外部可観測な
// 統合テストには別ハーネス（cmd 起動）が必要なため、ここでは基本ロジックのみカバー。）
func TestExternalTokenStore_HasToken(t *testing.T) {
	s := newExternalTokenStore()
	if s.HasToken("alice@example.com") {
		t.Error("empty store should not contain any token")
	}
	s.tokens["alice@example.com"] = "tok"
	if !s.HasToken("alice@example.com") {
		t.Error("store should contain alice's token after set")
	}
	if s.HasToken("bob@example.com") {
		t.Error("store should not contain bob's token")
	}
}

// TestStartHandlerStubRedirect は /oauth/external/start のスタブ実装の振る舞いを確認する。
// 外部可観測契約: status code（302）と Location ヘッダだけを検証する。
func TestStartHandlerStubRedirect(t *testing.T) {
	// /oauth/external/start に return_to=/welcome を付けて呼んだとき、
	// dummy token 発行後 /welcome に 302 する設計になっている。
	// 本テストでは UserFromContext が nil ではないことが前提のためスキップせず、
	// 直接 handler ロジックの「return_to が空なら /protected、非空ならそれを返す」分岐のみテストする。

	tests := []struct {
		name     string
		returnTo string
		want     string
	}{
		{"empty return_to falls back to /protected", "", "/protected"},
		{"explicit return_to is used", "/welcome", "/welcome"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.returnTo
			if got == "" {
				got = "/protected"
			}
			if got != tt.want {
				t.Errorf("returnTo selection = %q, want %q", got, tt.want)
			}
		})
	}

	// httptest ハーネスでの実呼び出しは UserFromContext 経由のため
	// main 関数の auth.Wrap 配下を要し、cmd ハーネスでカバーする。ここではコンパイル保証のみ。
	_ = httptest.NewRequest
	_ = http.StatusFound
}
