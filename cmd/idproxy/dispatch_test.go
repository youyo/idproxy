package main

import (
	"errors"
	"os"
	"reflect"
	"testing"
)

// TestRootRouter は dispatch がサブコマンドを正しく振り分けることを確認する。
func TestRootRouter(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantServe bool
		wantSetup []string // 期待する setup 引数（nil なら setup は呼ばれない）
	}{
		{name: "empty_args", args: []string{}, wantServe: true},
		{name: "serve_only", args: []string{"serve"}, wantServe: true},
		{name: "serve_with_flag", args: []string{"serve", "-some-flag"}, wantServe: true},
		{name: "setup_entra_id", args: []string{"setup", "entra-id"}, wantSetup: []string{"entra-id"}},
		{name: "setup_entra_id_flags", args: []string{"setup", "entra-id", "--instance-name", "amg"}, wantSetup: []string{"entra-id", "--instance-name", "amg"}},
		{name: "leading_flag_serve_compat", args: []string{"--some-flag"}, wantServe: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origServe, origSetup, origArgs := runServeFn, runSetupFn, copyArgs()
			defer func() {
				runServeFn = origServe
				runSetupFn = origSetup
				setArgs(origArgs)
			}()

			var serveCalled bool
			var gotSetupArgs []string
			runServeFn = func() error {
				serveCalled = true
				return nil
			}
			runSetupFn = func(args []string) error {
				gotSetupArgs = args
				return nil
			}

			if err := dispatch(tt.args); err != nil {
				t.Fatalf("dispatch error: %v", err)
			}

			if tt.wantServe && !serveCalled {
				t.Errorf("expected runServeFn to be called")
			}
			if tt.wantSetup != nil {
				if !reflect.DeepEqual(gotSetupArgs, tt.wantSetup) {
					t.Errorf("setup args = %v, want %v", gotSetupArgs, tt.wantSetup)
				}
			} else if gotSetupArgs != nil {
				t.Errorf("runSetupFn unexpectedly called with %v", gotSetupArgs)
			}
		})
	}
}

func TestRootRouter_UnknownSubcommand(t *testing.T) {
	origServe, origSetup, origArgs := runServeFn, runSetupFn, copyArgs()
	defer func() {
		runServeFn = origServe
		runSetupFn = origSetup
		setArgs(origArgs)
	}()
	runServeFn = func() error { return nil }
	runSetupFn = func(args []string) error { return nil }

	err := dispatch([]string{"unknown-command"})
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
}

func TestRootRouter_PropagatesError(t *testing.T) {
	origServe, origSetup, origArgs := runServeFn, runSetupFn, copyArgs()
	defer func() {
		runServeFn = origServe
		runSetupFn = origSetup
		setArgs(origArgs)
	}()

	want := errors.New("setup failed")
	runServeFn = func() error { return nil }
	runSetupFn = func(args []string) error { return want }

	err := dispatch([]string{"setup", "entra-id"})
	if !errors.Is(err, want) {
		t.Errorf("dispatch error = %v, want %v", err, want)
	}
}

// TestServeBackwardCompat は引数なし、または "serve" のみ で従来の runServe 経路が
// 走ることを確認する。
func TestServeBackwardCompat(t *testing.T) {
	origServe, origSetup, origArgs := runServeFn, runSetupFn, copyArgs()
	defer func() {
		runServeFn = origServe
		runSetupFn = origSetup
		setArgs(origArgs)
	}()

	var calls int
	runServeFn = func() error {
		calls++
		return nil
	}
	runSetupFn = func(args []string) error {
		t.Fatalf("setup should not be called; got args=%v", args)
		return nil
	}

	for _, args := range [][]string{nil, {}, {"serve"}} {
		if err := dispatch(args); err != nil {
			t.Fatalf("dispatch(%v) error: %v", args, err)
		}
	}
	if calls != 3 {
		t.Errorf("runServeFn calls = %d, want 3", calls)
	}
}

// copyArgs / setArgs は os.Args を保護するヘルパー。
// dispatch は "serve" 経路で os.Args を書き換えるため、テスト中の差し込み・復元に使う。
func copyArgs() []string {
	out := make([]string, len(os.Args))
	copy(out, os.Args)
	return out
}

func setArgs(a []string) {
	os.Args = a
}
