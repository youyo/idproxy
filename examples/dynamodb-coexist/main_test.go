package main

import (
	"strings"
	"testing"

	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// TestAppPK_NamespaceIsolation は利用側 PK が idproxy のキー空間と衝突しないことを確認する。
// idproxy が使う PK プレフィクス（store/dynamodb.go の sessionPK / authCodePK 等）:
//
//   - session:
//   - authcode:
//   - accesstoken:
//   - client:
//   - refreshtoken:
//   - familyrevoked:
//
// 利用側は _app: プレフィクスを採用するため、これらと先頭一致しないこと。
func TestAppPK_NamespaceIsolation(t *testing.T) {
	idproxyPrefixes := []string{
		"session:",
		"authcode:",
		"accesstoken:",
		"client:",
		"refreshtoken:",
		"familyrevoked:",
	}
	key := appPK("alice@example.com")
	pkAttr, ok := key["pk"]
	if !ok {
		t.Fatal("pk attribute missing")
	}
	sMember, ok := pkAttr.(*ddbtypes.AttributeValueMemberS)
	if !ok {
		t.Fatalf("pk attribute should be *AttributeValueMemberS, got %T", pkAttr)
	}
	v := sMember.Value
	for _, p := range idproxyPrefixes {
		if strings.HasPrefix(v, p) {
			t.Errorf("app PK %q must not start with idproxy reserved prefix %q", v, p)
		}
	}
	want := "_app:user:alice@example.com"
	if v != want {
		t.Errorf("app PK = %q, want %q", v, want)
	}
}
