package idproxy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// S256Challenge は RFC 7636 S256 メソッドでコードチャレンジを生成する。
// code_verifier を SHA-256 ハッシュし、base64url（パディングなし）でエンコードして返す。
//
// OAuth 2.1 では S256 のみが必須であり、plain メソッドは禁止されている。
func S256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// VerifyS256 は RFC 7636 S256 メソッドでコードチャレンジを検証する。
// SHA256(verifier) の base64url が challenge と一致する場合に true を返す。
// verifier または challenge が空文字列の場合は false を返す。
//
// タイミングサイドチャネル攻撃を防ぐため、crypto/subtle.ConstantTimeCompare で比較する。
func VerifyS256(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	expected := []byte(S256Challenge(verifier))
	actual := []byte(challenge)
	return subtle.ConstantTimeCompare(expected, actual) == 1
}
