package idproxy

import (
	"strings"
	"testing"
)

// RFC 7636 Appendix B のテストベクター
const (
	rfc7636Verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfc7636Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	minVerifier      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"                                                                                       // 43文字（最短）
	maxVerifier      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 128文字（最長）
)

// TestS256Challenge は S256Challenge 関数のテスト。
// T01: RFC 7636 Appendix B テストベクター
// T02: 43文字の最短 verifier
// E01: 128文字の最長 verifier
func TestS256Challenge(t *testing.T) {
	t.Run("T01_RFC7636_テストベクター", func(t *testing.T) {
		got := S256Challenge(rfc7636Verifier)
		if got != rfc7636Challenge {
			t.Errorf("S256Challenge(%q) = %q, want %q", rfc7636Verifier, got, rfc7636Challenge)
		}
	})

	t.Run("T02_最短43文字のverifier", func(t *testing.T) {
		got := S256Challenge(minVerifier)
		// SHA256 は 32 バイト → base64url（パディングなし）= 43 文字
		if len(got) != 43 {
			t.Errorf("S256Challenge(43-char verifier) length = %d, want 43", len(got))
		}
		// パディング文字（=）が含まれていないことを確認
		if strings.Contains(got, "=") {
			t.Errorf("S256Challenge result contains padding '=': %q", got)
		}
	})

	t.Run("E01_最長128文字のverifier", func(t *testing.T) {
		got := S256Challenge(maxVerifier)
		if len(got) != 43 {
			t.Errorf("S256Challenge(128-char verifier) length = %d, want 43", len(got))
		}
		if strings.Contains(got, "=") {
			t.Errorf("S256Challenge result contains padding '=': %q", got)
		}
	})

	t.Run("A01_空文字列verifier", func(t *testing.T) {
		got := S256Challenge("")
		// SHA256("") も有効な計算結果を返す（空文字列ではない）
		if got == "" {
			t.Error("S256Challenge(\"\") returned empty string, want non-empty")
		}
		if len(got) != 43 {
			t.Errorf("S256Challenge(\"\") length = %d, want 43", len(got))
		}
	})
}

// TestVerifyS256 は VerifyS256 関数のテスト。
// T03: 正しいペア → true
// T04: 誤った verifier → false
// T05: 空文字 verifier → false
// T06: 空文字 challenge → false
// A02: 不正な base64url 文字列 → false
// E02: パディング付き challenge → false
func TestVerifyS256(t *testing.T) {
	t.Run("T03_正しいペアはtrue", func(t *testing.T) {
		if !VerifyS256(rfc7636Verifier, rfc7636Challenge) {
			t.Error("VerifyS256(correct verifier, correct challenge) = false, want true")
		}
	})

	t.Run("T04_誤ったverifierはfalse", func(t *testing.T) {
		if VerifyS256("wrong-verifier-string-that-is-invalid", rfc7636Challenge) {
			t.Error("VerifyS256(wrong verifier, correct challenge) = true, want false")
		}
	})

	t.Run("T05_空のverifierはfalse", func(t *testing.T) {
		if VerifyS256("", rfc7636Challenge) {
			t.Error("VerifyS256(\"\", challenge) = true, want false")
		}
	})

	t.Run("T06_空のchallengeはfalse", func(t *testing.T) {
		if VerifyS256(rfc7636Verifier, "") {
			t.Error("VerifyS256(verifier, \"\") = true, want false")
		}
	})

	t.Run("A02_不正なbase64url文字列はfalse", func(t *testing.T) {
		if VerifyS256(rfc7636Verifier, "!!!invalid-base64url!!!") {
			t.Error("VerifyS256(verifier, invalid-base64) = true, want false")
		}
	})

	t.Run("E02_パディング付きchallengeはfalse", func(t *testing.T) {
		// base64url のパディング付き文字列（正規の S256 出力はパディングなし）
		paddedChallenge := rfc7636Challenge + "="
		if VerifyS256(rfc7636Verifier, paddedChallenge) {
			t.Error("VerifyS256(verifier, padded-challenge) = true, want false")
		}
	})
}
