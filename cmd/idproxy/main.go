package main

import (
	"fmt"
	"os"

	"github.com/youyo/idproxy/cmd/idproxy/setup"
)

// runServeFn / runSetupFn はテスト注入用の関数変数。
// router の経路を検証する際にスタブへ差し替えるため var にしている。
var (
	runServeFn = runServe
	runSetupFn = setup.RunCLI
)

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// dispatch は os.Args[1:] を受け取り、サブコマンドに応じたハンドラーを呼び出す。
//   - "setup"             → runSetupFn(args[1:])
//   - "serve" / 空        → runServeFn()（後方互換）
//   - "-h" / "--help"     → ルーター usage を出力
//   - その他              → エラー
//
// 注: serve 用フラグは引き続き flag.CommandLine（グローバル）を使う。
// runServe 内で flag.Parse() を呼ぶため、ここで os.Args を書き換える必要がある場合は
// セットアップサブコマンド側に分岐した後で行う。
func dispatch(args []string) error {
	if len(args) == 0 {
		return runServeFn()
	}
	switch args[0] {
	case "setup":
		return runSetupFn(args[1:])
	case "serve":
		// "serve" を取り除いたうえで flag.Parse() に残りを通すため os.Args を縮める
		os.Args = append([]string{os.Args[0]}, args[1:]...)
		return runServeFn()
	case "-h", "--help":
		// 従来の `idproxy --help` は serve のヘルプを表示していた。後方互換性を維持する。
		return runServeFn()
	default:
		// 不明なコマンド → 既存の serve は flag を直接読むため、先頭が "-"（フラグ）なら
		// 後方互換のため serve として実行する。
		if args[0][0] == '-' {
			return runServeFn()
		}
		printRootUsage(os.Stderr)
		return fmt.Errorf("unknown command: %s", args[0])
	}
}
