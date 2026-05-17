package setup

import (
	"fmt"
	"regexp"
	"strings"
)

// instanceNameRe はリソース識別子として有効な文字列を表す正規表現。
// - 先頭は英字
// - 続く文字列は英数字・アンダースコア・ハイフン
// - 全体長は 3〜63 文字
var instanceNameRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{2,62}$`)

// ValidateInstanceName はリソース識別子として妥当かを検証する。
// SSM パラメータ名や Azure リソース名に流用できるよう、aws プレフィックスは禁止する。
func ValidateInstanceName(name string) error {
	if name == "" {
		return fmt.Errorf("instance name is required")
	}
	if !instanceNameRe.MatchString(name) {
		// より具体的なメッセージを返す
		if len(name) < 3 {
			return fmt.Errorf("instance name %q is too short (must be 3..63 characters)", name)
		}
		if len(name) > 63 {
			return fmt.Errorf("instance name %q is too long (must be 3..63 characters)", name)
		}
		first := name[0]
		if (first < 'a' || first > 'z') && (first < 'A' || first > 'Z') {
			return fmt.Errorf("instance name %q must start with a letter", name)
		}
		return fmt.Errorf("instance name %q contains invalid characters (allowed: a-z A-Z 0-9 _ -)", name)
	}
	if strings.HasPrefix(strings.ToLower(name), "aws") {
		return fmt.Errorf("instance name %q must not start with 'aws' (reserved by AWS SSM)", name)
	}
	return nil
}
