package setup

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// CommandExecutor は外部コマンド実行を抽象化するインターフェース。
// 実 CLI 実行（RealExecutor）とテスト用スタブ（StubExecutor）を差し替え可能にする。
type CommandExecutor interface {
	// LookPath は exec.LookPath と同等。コマンドの PATH 検索を行う。
	LookPath(name string) (string, error)
	// Output はコマンドを実行し標準出力を返す。失敗時は stderr を含むエラーを返す。
	Output(ctx context.Context, name string, args []string) ([]byte, error)
}

// RealExecutor は実際の os/exec を用いた本番実装。
type RealExecutor struct{}

// LookPath は exec.LookPath をそのまま呼ぶ。
func (RealExecutor) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// Output は exec.CommandContext を用いて外部コマンドを実行し標準出力を返す。
// 失敗時は stderr の内容を含むエラーを返す。
func (RealExecutor) Output(ctx context.Context, name string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// StubCall はテスト用に記録される実行履歴。
type StubCall struct {
	Name string
	Args []string
}

// StubResponse はテスト用にあらかじめ用意した応答。
type StubResponse struct {
	Out []byte
	Err error
}

// StubExecutor はテスト用の CommandExecutor 実装。
// Responses のキーは "name args[0] args[1] ..." の前方一致で照合し、
// 最長一致が選ばれる。
type StubExecutor struct {
	// Calls は実行履歴（FIFO）。
	Calls []StubCall
	// Responses は前方一致でマッチさせる応答テーブル。
	Responses map[string]StubResponse
	// LookPathFunc は LookPath の挙動を差し替えるフック。nil の場合は常に成功扱い。
	LookPathFunc func(name string) (string, error)
}

// LookPath は LookPathFunc に委譲する。未設定時は受け取った name をそのまま返す。
func (s *StubExecutor) LookPath(name string) (string, error) {
	if s.LookPathFunc != nil {
		return s.LookPathFunc(name)
	}
	return name, nil
}

// Output は前方一致でレスポンスを返す。最長一致が優先される。
func (s *StubExecutor) Output(_ context.Context, name string, args []string) ([]byte, error) {
	s.Calls = append(s.Calls, StubCall{Name: name, Args: append([]string(nil), args...)})

	key := name
	if len(args) > 0 {
		key = name + " " + strings.Join(args, " ")
	}

	var bestKey string
	var bestResp StubResponse
	matched := false
	for k, v := range s.Responses {
		if !hasTokenPrefix(key, k) {
			continue
		}
		if !matched || len(k) > len(bestKey) {
			bestKey = k
			bestResp = v
			matched = true
		}
	}
	if !matched {
		return nil, fmt.Errorf("StubExecutor: no response registered for %q", key)
	}
	return bestResp.Out, bestResp.Err
}

// hasTokenPrefix は s が prefix を「トークン境界」で開始するかを判定する。
// たとえば prefix="az ad app" は s="az ad app list" にはマッチするが
// s="az ad apparel" にはマッチしない。
func hasTokenPrefix(s, prefix string) bool {
	if s == prefix {
		return true
	}
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	// 直後がスペースなら token boundary
	return s[len(prefix)] == ' '
}
