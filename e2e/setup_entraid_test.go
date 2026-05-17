//go:build e2e

package e2e_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestSetupEntraID_E2E は実際の idproxy バイナリを使って
// setup entra-id のエンドツーエンド動作を検証する。
// IDPROXY_E2E=1 のときのみ実行される。
func TestSetupEntraID_E2E(t *testing.T) {
	if os.Getenv("IDPROXY_E2E") == "" {
		t.Skip("E2E tests require IDPROXY_E2E=1")
	}

	// idproxy バイナリをビルド
	binPath := filepath.Join(t.TempDir(), "idproxy")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	build := exec.Command("go", "build", "-o", binPath, "./cmd/idproxy")
	build.Dir = repoRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	// fake-az のパスを PATH の先頭に置く
	fakeBinDir := filepath.Join(repoRoot(t), "e2e", "testdata", "fake-bin")
	callLog := filepath.Join(t.TempDir(), "az-calls.log")

	cmd := exec.Command(binPath, "setup", "entra-id",
		"--non-interactive",
		"--instance-name", "testamg",
		"--external-url", "https://example.com",
	)
	cmd.Env = append(os.Environ(),
		"PATH="+fakeBinDir+":"+os.Getenv("PATH"),
		"FAKE_AZ_CALL_LOG="+callLog,
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, out)
	}

	// 成功サマリーが stdout に含まれること
	if !strings.Contains(string(out), "Entra ID Setup Complete") {
		t.Errorf("expected 'Entra ID Setup Complete' in output, got:\n%s", out)
	}
	if !strings.Contains(string(out), "OIDC_CLIENT_ID=test-app-id-1234") {
		t.Errorf("expected OIDC_CLIENT_ID in output, got:\n%s", out)
	}

	// fake-az が呼ばれた記録を確認
	logBytes, err := os.ReadFile(callLog)
	if err != nil {
		t.Fatalf("cannot read call log: %v", err)
	}
	calls := string(logBytes)
	for _, want := range []string{
		"ad app list",
		"ad app create",
		"ad app credential reset",
		"ad app show",
		"account show",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("expected az call %q, got:\n%s", want, calls)
		}
	}
}

// TestSetupEntraID_E2E_InvalidInstanceName は無効な instance-name でエラーになることを確認。
func TestSetupEntraID_E2E_InvalidInstanceName(t *testing.T) {
	if os.Getenv("IDPROXY_E2E") == "" {
		t.Skip("E2E tests require IDPROXY_E2E=1")
	}

	binPath := filepath.Join(t.TempDir(), "idproxy")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	build := exec.Command("go", "build", "-o", binPath, "./cmd/idproxy")
	build.Dir = repoRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	// fake-az のパスを PATH の先頭に置く（az 存在チェックを通過させるため）
	fakeBinDir := filepath.Join(repoRoot(t), "e2e", "testdata", "fake-bin")

	cmd := exec.Command(binPath, "setup", "entra-id",
		"--non-interactive",
		"--instance-name", "awsbad", // "aws" プレフィックス禁止
		"--external-url", "https://example.com",
	)
	cmd.Env = append(os.Environ(),
		"PATH="+fakeBinDir+":"+os.Getenv("PATH"),
	)

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error for invalid instance-name, got success\noutput: %s", out)
	}
	if !strings.Contains(string(out), "aws") {
		t.Errorf("expected 'aws' in error message, got:\n%s", out)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	// go list -m -f {{.Dir}} でモジュールルートを取得
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		t.Fatalf("cannot find module root: %v", err)
	}
	return strings.TrimSpace(string(out))
}
