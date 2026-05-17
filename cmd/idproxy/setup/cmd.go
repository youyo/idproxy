package setup

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/AlecAivazis/survey/v2"
)

// Options は setup entra-id サブコマンドの入力。
// テスト時は Exec / Stdout / Stderr を差し替えて検証する。
type Options struct {
	InstanceName   string
	ExternalURL    string
	PathPrefix     string
	AppID          string
	RotateSecret   bool
	NonInteractive bool

	// 注入ポイント
	Exec   CommandExecutor
	Stdout io.Writer
	Stderr io.Writer
}

// CallbackURI は ExternalURL + PathPrefix + "/callback" を組み立てる。
// 規則は runtime（auth.go の prefix + "/callback"）と一致させる。
//   - ExternalURL 末尾のスラッシュは除去
//   - PathPrefix は先頭スラッシュを保証（空文字なら付けない）
func CallbackURI(externalURL, pathPrefix string) string {
	base := strings.TrimRight(externalURL, "/")
	prefix := pathPrefix
	if prefix != "" && !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return base + prefix + "/callback"
}

// RunCLI は CLI から呼ばれるエントリポイント。
// 引数（os.Args[2:] 相当）をパースし、Run を呼ぶ。
func RunCLI(args []string) error {
	fs := flag.NewFlagSet("setup entra-id", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { printSetupUsage(fs.Output()) }
	var opts Options
	fs.StringVar(&opts.InstanceName, "instance-name", "", "リソース識別子（必須、非対話時）")
	fs.StringVar(&opts.ExternalURL, "external-url", "", "公開URL（必須、非対話時）")
	fs.StringVar(&opts.PathPrefix, "path-prefix", "", "PATH_PREFIX（オプション）")
	fs.StringVar(&opts.AppID, "app-id", "", "既存アプリID（N>1競合時に指定）")
	fs.BoolVar(&opts.RotateSecret, "rotate-secret", false, "既存アプリの client_secret を再生成する")
	fs.BoolVar(&opts.NonInteractive, "non-interactive", false, "全入力をフラグから取得（E2E/CI 用）")

	// サブサブコマンド: 先頭引数が "entra-id" であることを期待する
	if len(args) == 0 {
		printSetupUsage(os.Stderr)
		return fmt.Errorf("subcommand required: entra-id")
	}
	switch args[0] {
	case "entra-id":
		// ok
	case "-h", "--help":
		printSetupUsage(os.Stdout)
		return nil
	default:
		printSetupUsage(os.Stderr)
		return fmt.Errorf("unknown setup subcommand: %s", args[0])
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			// --help / -h は flag.ContinueOnError 下では ErrHelp として返るが、
			// ユーザーから見れば正常終了として扱う。
			return nil
		}
		return err
	}

	opts.Exec = RealExecutor{}
	opts.Stdout = os.Stdout
	opts.Stderr = os.Stderr
	return Run(context.Background(), opts)
}

func printSetupUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: idproxy setup entra-id [flags]

Entra ID のアプリ登録を自動化する。

Flags:
  --instance-name string    リソース識別子（例: amg）
  --external-url string     公開URL（例: https://proxy.example.com）
  --path-prefix string      PATH_PREFIX（オプション）
  --app-id string           既存アプリID（N>1競合時に明示指定）
  --rotate-secret           既存アプリの client_secret を再生成する
  --non-interactive         全入力をフラグから取得（E2E/CI 用）
`)
}

// Run はオーケストレーション本体。CLI / テストから呼ばれる。
func Run(ctx context.Context, opts Options) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Exec == nil {
		opts.Exec = RealExecutor{}
	}

	if _, err := opts.Exec.LookPath("az"); err != nil {
		return fmt.Errorf("az CLI not found in PATH; install from https://learn.microsoft.com/cli/azure/install-azure-cli (%w)", err)
	}

	// 途中失敗時も取得済み secret を表示するための defer
	// （アプリ登録は完了しているが後続ステップが失敗した場合）
	var partialSecret string
	defer func() {
		if partialSecret != "" {
			// エラーで終了してもユーザーが secret をコピーできるよう Stderr に出力
			_, _ = fmt.Fprintf(opts.Stderr, "\n[PARTIAL SUCCESS] Client secret was generated but setup did not complete.\n")
			_, _ = fmt.Fprintf(opts.Stderr, "OIDC_CLIENT_SECRET=%s\n", partialSecret)
			_, _ = fmt.Fprintln(opts.Stderr, "Re-run with --rotate-secret=false to continue setup without generating a new secret.")
		}
	}()

	if !opts.NonInteractive {
		if err := promptMissing(&opts); err != nil {
			return err
		}
	}
	if opts.InstanceName == "" {
		return fmt.Errorf("--instance-name is required")
	}
	if err := ValidateInstanceName(opts.InstanceName); err != nil {
		return err
	}
	if err := validateExternalURL(opts.ExternalURL); err != nil {
		return err
	}

	displayName := "idproxy-" + opts.InstanceName
	az := NewAZClient(opts.Exec)

	var app *App
	var err error
	if opts.AppID != "" {
		// --app-id 指定時は検索をスキップし、その AppID を ObjectID 兼用として扱う。
		// az ad app の --id は AppID/ObjectID のどちらでも受け付けるためそのまま使う。
		app = &App{AppID: opts.AppID, ObjectID: opts.AppID, DisplayName: displayName}
	} else {
		app, err = az.FindApp(ctx, displayName)
		if err != nil {
			var multi *ErrMultipleAppsFound
			if errors.As(err, &multi) {
				_, _ = fmt.Fprintln(opts.Stderr, "Multiple apps found with the same displayName:")
				for _, c := range multi.Candidates {
					_, _ = fmt.Fprintf(opts.Stderr, "  - %s (objectId=%s)\n", c.AppID, c.ObjectID)
				}
				return fmt.Errorf("multiple apps found for %q; specify --app-id to choose one", displayName)
			}
			return err
		}
	}

	var secret string
	if app == nil {
		_, _ = fmt.Fprintf(opts.Stdout, "Creating new app registration: %s\n", displayName)
		app, err = az.CreateApp(ctx, displayName)
		if err != nil {
			return err
		}
		secret, err = az.ResetCredential(ctx, app.AppID)
		if err != nil {
			return err
		}
		partialSecret = secret
	} else {
		_, _ = fmt.Fprintf(opts.Stdout, "Reusing existing app: %s (appId=%s)\n", displayName, app.AppID)
		if opts.RotateSecret {
			secret, err = az.ResetCredential(ctx, app.AppID)
			if err != nil {
				return err
			}
			partialSecret = secret
		}
	}

	callback := CallbackURI(opts.ExternalURL, opts.PathPrefix)
	existing, err := az.GetRedirectURIs(ctx, app.AppID)
	if err != nil {
		return err
	}
	merged, changed := mergeRedirectURIs(existing, callback)
	if changed {
		if err := az.SetRedirectURIs(ctx, app.AppID, merged); err != nil {
			return err
		}
	}

	tenantID, err := az.GetTenantID(ctx)
	if err != nil {
		// TenantID 取得失敗はサマリー表示に影響するだけなので警告で続行する。
		// アプリ登録とリダイレクト URI 設定は完了しているため処理を止めない。
		_, _ = fmt.Fprintf(opts.Stderr, "warning: could not retrieve tenant ID (%v); OIDC_ISSUER will be incomplete\n", err)
		tenantID = "(unknown)"
	}

	// ここまで到達したら partial success は不要
	partialSecret = ""
	printSummary(opts.Stdout, summary{
		DisplayName: displayName,
		AppID:       app.AppID,
		TenantID:    tenantID,
		Callback:    callback,
		Secret:      secret,
	})
	return nil
}

// mergeRedirectURIs は既存 URI に callback を追加した結果と、追加が必要かを返す。
func mergeRedirectURIs(existing []string, callback string) ([]string, bool) {
	if slices.Contains(existing, callback) {
		return existing, false
	}
	return append(slices.Clone(existing), callback), true
}

type summary struct {
	DisplayName string
	AppID       string
	TenantID    string
	Callback    string
	Secret      string
}

func printSummary(w io.Writer, s summary) {
	issuer := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", s.TenantID)
	_, _ = fmt.Fprintln(w, "=== Entra ID Setup Complete ===")
	_, _ = fmt.Fprintf(w, "App:             %s\n", s.DisplayName)
	_, _ = fmt.Fprintf(w, "Client ID:       %s\n", s.AppID)
	_, _ = fmt.Fprintf(w, "Tenant:          %s\n", s.TenantID)
	_, _ = fmt.Fprintf(w, "OIDC Issuer:     %s\n", issuer)
	_, _ = fmt.Fprintf(w, "Redirect URI:    %s\n", s.Callback)
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "Set these environment variables:")
	_, _ = fmt.Fprintf(w, "OIDC_ISSUER=%s\n", issuer)
	_, _ = fmt.Fprintf(w, "OIDC_CLIENT_ID=%s\n", s.AppID)
	if s.Secret != "" {
		_, _ = fmt.Fprintf(w, "OIDC_CLIENT_SECRET=%s\n", s.Secret)
	}
}

// validateExternalURL は外部公開 URL の最小検証を行う。
// 規則は config.go の ExternalURL 検証（Validate メソッド）と揃える。
func validateExternalURL(u string) error {
	if u == "" {
		return fmt.Errorf("--external-url is required")
	}
	if !strings.HasPrefix(u, "https://") &&
		!strings.HasPrefix(u, "http://localhost") &&
		!strings.HasPrefix(u, "http://127.0.0.1") &&
		!strings.HasPrefix(u, "http://[::1]") {
		return fmt.Errorf("--external-url must start with https:// (got %q)", u)
	}
	return nil
}

// promptMissing は対話モードで未入力のフラグを補完する。
func promptMissing(opts *Options) error {
	if opts.InstanceName == "" {
		q := &survey.Input{Message: "Instance name (e.g. amg):"}
		if err := survey.AskOne(q, &opts.InstanceName); err != nil {
			return err
		}
	}
	if opts.ExternalURL == "" {
		q := &survey.Input{Message: "External URL (e.g. https://proxy.example.com):"}
		if err := survey.AskOne(q, &opts.ExternalURL); err != nil {
			return err
		}
	}
	return nil
}
