package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
)

// ValidateExternalURL ---------------------------------------------------------

func TestValidateExternalURL(t *testing.T) {
	tests := []struct {
		in      string
		wantErr bool
	}{
		{"https://example.com", false},
		{"https://proxy.example.com/path", false},
		{"http://localhost:8080", false},
		{"http://127.0.0.1:8080", false},
		{"http://[::1]:8080", false},
		{"http://example.com", true},  // http は不可
		{"ftp://example.com", true},
		{"", true},
	}
	for _, tt := range tests {
		err := validateExternalURL(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateExternalURL(%q) error=%v, wantErr=%v", tt.in, err, tt.wantErr)
		}
	}
}

// ValidateInstanceName --------------------------------------------------------

func TestValidateInstanceName_valid(t *testing.T) {
	valid := []string{
		"amg",
		"amg-sandbox",
		"amg_v2",
		"prod-1",
		"A1bc",
		strings.Repeat("a", 63), // 63文字（境界値: 1 + 62 = 63）
	}
	for _, name := range valid {
		t.Run(name, func(t *testing.T) {
			if err := ValidateInstanceName(name); err != nil {
				t.Errorf("ValidateInstanceName(%q) = %v, want nil", name, err)
			}
		})
	}
}

func TestValidateInstanceName_invalid(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"aws_prefix", "awsfoo"},
		{"starts_with_digit", "1abc"},
		{"starts_with_hyphen", "-abc"},
		{"too_long", strings.Repeat("a", 64)}, // 64文字（境界値超え）
		{"too_short", "ab"},                   // 最短は 3 文字（1 + {2,62}）
		{"invalid_char", "abc!"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateInstanceName(tt.in); err == nil {
				t.Errorf("ValidateInstanceName(%q) = nil, want error", tt.in)
			}
		})
	}
}

// CallbackURI -----------------------------------------------------------------

func TestCallbackURI(t *testing.T) {
	tests := []struct {
		name        string
		externalURL string
		pathPrefix  string
		want        string
	}{
		{
			name:        "no_prefix",
			externalURL: "https://example.com",
			pathPrefix:  "",
			want:        "https://example.com/callback",
		},
		{
			name:        "trailing_slash_external",
			externalURL: "https://example.com/",
			pathPrefix:  "",
			want:        "https://example.com/callback",
		},
		{
			name:        "with_prefix_leading_slash",
			externalURL: "https://example.com",
			pathPrefix:  "/auth",
			want:        "https://example.com/auth/callback",
		},
		{
			name:        "with_prefix_no_leading_slash",
			externalURL: "https://example.com",
			pathPrefix:  "auth",
			want:        "https://example.com/auth/callback",
		},
		{
			name:        "trailing_slash_external_with_prefix",
			externalURL: "https://example.com/",
			pathPrefix:  "/auth",
			want:        "https://example.com/auth/callback",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CallbackURI(tt.externalURL, tt.pathPrefix)
			if got != tt.want {
				t.Errorf("CallbackURI(%q,%q) = %q, want %q", tt.externalURL, tt.pathPrefix, got, tt.want)
			}
		})
	}
}

// StubExecutor ---------------------------------------------------------------

func TestStubExecutor_Output_MatchesPrefix(t *testing.T) {
	stub := &StubExecutor{
		Responses: map[string]StubResponse{
			"az ad app list": {Out: []byte("[]")},
		},
	}
	out, err := stub.Output(context.Background(), "az", []string{"ad", "app", "list", "--filter", "foo"})
	if err != nil {
		t.Fatalf("Output error: %v", err)
	}
	if string(out) != "[]" {
		t.Errorf("Output = %q, want %q", out, "[]")
	}
	if len(stub.Calls) != 1 {
		t.Fatalf("Calls len = %d, want 1", len(stub.Calls))
	}
}

func TestStubExecutor_Output_LongestPrefixWins(t *testing.T) {
	stub := &StubExecutor{
		Responses: map[string]StubResponse{
			"az ad app":      {Out: []byte("short")},
			"az ad app list": {Out: []byte("long")},
		},
	}
	out, err := stub.Output(context.Background(), "az", []string{"ad", "app", "list"})
	if err != nil {
		t.Fatalf("Output error: %v", err)
	}
	if string(out) != "long" {
		t.Errorf("Output = %q, want %q (longest prefix should win)", out, "long")
	}
}

func TestStubExecutor_Output_NoMatch(t *testing.T) {
	stub := &StubExecutor{}
	_, err := stub.Output(context.Background(), "az", []string{"unknown"})
	if err == nil {
		t.Fatal("Output expected error for unmatched command")
	}
}

func TestStubExecutor_LookPath(t *testing.T) {
	stub := &StubExecutor{
		LookPathFunc: func(name string) (string, error) {
			if name == "az" {
				return "/usr/bin/az", nil
			}
			return "", errors.New("not found")
		},
	}
	got, err := stub.LookPath("az")
	if err != nil {
		t.Fatalf("LookPath error: %v", err)
	}
	if got != "/usr/bin/az" {
		t.Errorf("LookPath = %q, want %q", got, "/usr/bin/az")
	}
}

// AZClient -------------------------------------------------------------------

func TestAZClient_FindApp_notFound(t *testing.T) {
	stub := &StubExecutor{
		Responses: map[string]StubResponse{
			"az ad app list": {Out: []byte("[]")},
		},
	}
	c := NewAZClient(stub)
	app, err := c.FindApp(context.Background(), "idproxy-foo")
	if err != nil {
		t.Fatalf("FindApp error: %v", err)
	}
	if app != nil {
		t.Errorf("FindApp = %+v, want nil", app)
	}
}

func TestAZClient_FindApp_found(t *testing.T) {
	jsonOut := `[{"appId":"app-1","id":"obj-1","displayName":"idproxy-foo"}]`
	stub := &StubExecutor{
		Responses: map[string]StubResponse{
			"az ad app list": {Out: []byte(jsonOut)},
		},
	}
	c := NewAZClient(stub)
	app, err := c.FindApp(context.Background(), "idproxy-foo")
	if err != nil {
		t.Fatalf("FindApp error: %v", err)
	}
	if app == nil {
		t.Fatal("FindApp = nil, want App")
	}
	if app.AppID != "app-1" || app.ObjectID != "obj-1" || app.DisplayName != "idproxy-foo" {
		t.Errorf("FindApp = %+v", app)
	}
}

func TestAZClient_FindApp_multiple(t *testing.T) {
	jsonOut := `[
		{"appId":"app-1","id":"obj-1","displayName":"idproxy-foo"},
		{"appId":"app-2","id":"obj-2","displayName":"idproxy-foo"}
	]`
	stub := &StubExecutor{
		Responses: map[string]StubResponse{
			"az ad app list": {Out: []byte(jsonOut)},
		},
	}
	c := NewAZClient(stub)
	_, err := c.FindApp(context.Background(), "idproxy-foo")
	if err == nil {
		t.Fatal("FindApp expected error")
	}
	var me *ErrMultipleAppsFound
	if !errors.As(err, &me) {
		t.Fatalf("FindApp error = %T, want *ErrMultipleAppsFound", err)
	}
	if len(me.Candidates) != 2 {
		t.Errorf("Candidates = %d, want 2", len(me.Candidates))
	}
}

func TestAZClient_CreateApp(t *testing.T) {
	jsonOut := `{"appId":"new-app","id":"new-obj","displayName":"idproxy-foo"}`
	stub := &StubExecutor{
		Responses: map[string]StubResponse{
			"az ad app create": {Out: []byte(jsonOut)},
		},
	}
	c := NewAZClient(stub)
	app, err := c.CreateApp(context.Background(), "idproxy-foo")
	if err != nil {
		t.Fatalf("CreateApp error: %v", err)
	}
	if app == nil || app.AppID != "new-app" || app.ObjectID != "new-obj" {
		t.Errorf("CreateApp = %+v", app)
	}
}

func TestAZClient_ResetCredential(t *testing.T) {
	jsonOut := `{"appId":"app-1","password":"the-secret","secretText":"the-secret","tenant":"tenant-1"}`
	stub := &StubExecutor{
		Responses: map[string]StubResponse{
			"az ad app credential reset": {Out: []byte(jsonOut)},
		},
	}
	c := NewAZClient(stub)
	secret, err := c.ResetCredential(context.Background(), "app-1")
	if err != nil {
		t.Fatalf("ResetCredential error: %v", err)
	}
	if secret != "the-secret" {
		t.Errorf("ResetCredential = %q, want %q", secret, "the-secret")
	}
}

func TestAZClient_GetRedirectURIs_null(t *testing.T) {
	stub := &StubExecutor{
		Responses: map[string]StubResponse{
			"az ad app show": {Out: []byte("null")},
		},
	}
	c := NewAZClient(stub)
	uris, err := c.GetRedirectURIs(context.Background(), "app-1")
	if err != nil {
		t.Fatalf("GetRedirectURIs error: %v", err)
	}
	if uris == nil {
		t.Fatal("uris is nil; want non-nil empty slice")
	}
	if len(uris) != 0 {
		t.Errorf("len(uris) = %d, want 0", len(uris))
	}
}

func TestAZClient_GetRedirectURIs_list(t *testing.T) {
	jsonOut := `["https://a.example.com/callback","https://b.example.com/callback"]`
	stub := &StubExecutor{
		Responses: map[string]StubResponse{
			"az ad app show": {Out: []byte(jsonOut)},
		},
	}
	c := NewAZClient(stub)
	uris, err := c.GetRedirectURIs(context.Background(), "app-1")
	if err != nil {
		t.Fatalf("GetRedirectURIs error: %v", err)
	}
	want := []string{"https://a.example.com/callback", "https://b.example.com/callback"}
	if !reflect.DeepEqual(uris, want) {
		t.Errorf("uris = %v, want %v", uris, want)
	}
}

func TestAZClient_SetRedirectURIs(t *testing.T) {
	stub := &StubExecutor{
		Responses: map[string]StubResponse{
			"az ad app update": {Out: []byte("")},
		},
	}
	c := NewAZClient(stub)
	err := c.SetRedirectURIs(context.Background(), "app-1", []string{
		"https://a.example.com/callback",
		"https://b.example.com/callback",
	})
	if err != nil {
		t.Fatalf("SetRedirectURIs error: %v", err)
	}
	if len(stub.Calls) != 1 {
		t.Fatalf("Calls len = %d, want 1", len(stub.Calls))
	}
	call := stub.Calls[0]
	if call.Name != "az" {
		t.Errorf("Name = %q, want %q", call.Name, "az")
	}
	// args が ad app update --id app-1 --web-redirect-uris uri1 uri2 を含むこと
	joined := strings.Join(call.Args, " ")
	for _, want := range []string{
		"ad app update",
		"--id app-1",
		"--web-redirect-uris",
		"https://a.example.com/callback",
		"https://b.example.com/callback",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q (got %q)", want, joined)
		}
	}
}

func TestAZClient_SetRedirectURIs_empty(t *testing.T) {
	stub := &StubExecutor{}
	c := NewAZClient(stub)
	// 空スライスでは az を呼ばずに nil を返す（無意味な呼び出し回避）
	err := c.SetRedirectURIs(context.Background(), "app-1", nil)
	if err != nil {
		t.Fatalf("SetRedirectURIs error: %v", err)
	}
	if len(stub.Calls) != 0 {
		t.Errorf("Calls len = %d, want 0 (empty slice should not invoke az)", len(stub.Calls))
	}
}

func TestAZClient_GetTenantID(t *testing.T) {
	jsonOut := `"tenant-xyz"`
	stub := &StubExecutor{
		Responses: map[string]StubResponse{
			"az account show": {Out: []byte(jsonOut)},
		},
	}
	c := NewAZClient(stub)
	tid, err := c.GetTenantID(context.Background())
	if err != nil {
		t.Fatalf("GetTenantID error: %v", err)
	}
	if tid != "tenant-xyz" {
		t.Errorf("GetTenantID = %q, want %q", tid, "tenant-xyz")
	}
}

// Run (Orchestration) --------------------------------------------------------

func TestRun_CreatesNewApp(t *testing.T) {
	stub := &StubExecutor{
		LookPathFunc: func(name string) (string, error) {
			if name == "az" {
				return "/usr/bin/az", nil
			}
			return "", errors.New("not found")
		},
		Responses: map[string]StubResponse{
			"az ad app list":            {Out: []byte("[]")},
			"az ad app create":          {Out: []byte(`{"appId":"new-app","id":"new-obj","displayName":"idproxy-amg"}`)},
			"az ad app credential reset": {Out: []byte(`{"secretText":"shhh"}`)},
			"az ad app show":            {Out: []byte("null")},
			"az ad app update":          {Out: []byte("")},
			"az account show":           {Out: []byte(`"tenant-1"`)},
		},
	}
	var out strings.Builder
	opts := Options{
		InstanceName:    "amg",
		ExternalURL:     "https://example.com",
		PathPrefix:      "",
		NonInteractive:  true,
		Exec:            stub,
		Stdout:          &out,
		Stderr:          &out,
	}
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run error: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"idproxy-amg",
		"new-app",
		"tenant-1",
		"https://login.microsoftonline.com/tenant-1/v2.0",
		"https://example.com/callback",
		"OIDC_CLIENT_SECRET=shhh", // 新規作成時は secret を出す
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\n=== output ===\n%s", want, got)
		}
	}
}

func TestRun_ReuseExistingApp_NoSecretPrinted(t *testing.T) {
	stub := &StubExecutor{
		LookPathFunc: func(name string) (string, error) { return "/usr/bin/az", nil },
		Responses: map[string]StubResponse{
			"az ad app list":   {Out: []byte(`[{"appId":"existing","id":"obj","displayName":"idproxy-amg"}]`)},
			"az ad app show":   {Out: []byte(`["https://example.com/callback"]`)},
			"az ad app update": {Out: []byte("")},
			"az account show":  {Out: []byte(`"tenant-1"`)},
		},
	}
	var out strings.Builder
	opts := Options{
		InstanceName:   "amg",
		ExternalURL:    "https://example.com",
		NonInteractive: true,
		Exec:           stub,
		Stdout:         &out,
		Stderr:         &out,
	}
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run error: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "existing") {
		t.Errorf("expected existing appId in output, got:\n%s", got)
	}
	if strings.Contains(got, "OIDC_CLIENT_SECRET=") {
		t.Errorf("OIDC_CLIENT_SECRET should not be printed when reusing existing app without rotation; got:\n%s", got)
	}
	// 既存 callback URI が含まれていれば SetRedirectURIs は呼ばれない（マージ後に変更がないため）
	for _, call := range stub.Calls {
		if strings.Join(call.Args, " ") == "ad app update --id obj --web-redirect-uris https://example.com/callback" {
			t.Errorf("SetRedirectURIs should not be invoked when callback already registered; got call %v", call.Args)
		}
	}
}

func TestRun_ReuseExistingApp_RotateSecret(t *testing.T) {
	stub := &StubExecutor{
		LookPathFunc: func(name string) (string, error) { return "/usr/bin/az", nil },
		Responses: map[string]StubResponse{
			"az ad app list":            {Out: []byte(`[{"appId":"existing","id":"obj","displayName":"idproxy-amg"}]`)},
			"az ad app credential reset": {Out: []byte(`{"secretText":"rotated"}`)},
			"az ad app show":            {Out: []byte(`["https://example.com/callback"]`)},
			"az account show":           {Out: []byte(`"tenant-1"`)},
		},
	}
	var out strings.Builder
	opts := Options{
		InstanceName:   "amg",
		ExternalURL:    "https://example.com",
		NonInteractive: true,
		RotateSecret:   true,
		Exec:           stub,
		Stdout:         &out,
		Stderr:         &out,
	}
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run error: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "OIDC_CLIENT_SECRET=rotated") {
		t.Errorf("expected rotated secret in output; got:\n%s", got)
	}
}

func TestRun_MultipleAppsFound_RequiresAppID(t *testing.T) {
	stub := &StubExecutor{
		LookPathFunc: func(name string) (string, error) { return "/usr/bin/az", nil },
		Responses: map[string]StubResponse{
			"az ad app list": {Out: []byte(`[
				{"appId":"app-1","id":"obj-1","displayName":"idproxy-amg"},
				{"appId":"app-2","id":"obj-2","displayName":"idproxy-amg"}
			]`)},
		},
	}
	var out strings.Builder
	opts := Options{
		InstanceName:   "amg",
		ExternalURL:    "https://example.com",
		NonInteractive: true,
		Exec:           stub,
		Stdout:         &out,
		Stderr:         &out,
	}
	err := Run(context.Background(), opts)
	if err == nil {
		t.Fatal("expected error for multiple apps")
	}
	if !strings.Contains(err.Error(), "--app-id") {
		t.Errorf("error should mention --app-id; got: %v", err)
	}
}

// mergeRedirectURIs ----------------------------------------------------------

func TestMergeRedirectURIs_newURI(t *testing.T) {
	existing := []string{"https://a.example.com/callback"}
	got, changed := mergeRedirectURIs(existing, "https://b.example.com/callback")
	if !changed {
		t.Error("changed = false, want true")
	}
	want := []string{"https://a.example.com/callback", "https://b.example.com/callback"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mergeRedirectURIs = %v, want %v", got, want)
	}
	// 元スライスが変更されていないことを確認
	if len(existing) != 1 {
		t.Errorf("existing modified: len = %d, want 1", len(existing))
	}
}

func TestMergeRedirectURIs_alreadyPresent(t *testing.T) {
	existing := []string{"https://a.example.com/callback"}
	got, changed := mergeRedirectURIs(existing, "https://a.example.com/callback")
	if changed {
		t.Error("changed = true, want false")
	}
	if !reflect.DeepEqual(got, existing) {
		t.Errorf("mergeRedirectURIs = %v, want %v", got, existing)
	}
}

func TestMergeRedirectURIs_emptyExisting(t *testing.T) {
	got, changed := mergeRedirectURIs([]string{}, "https://a.example.com/callback")
	if !changed {
		t.Error("changed = false, want true")
	}
	want := []string{"https://a.example.com/callback"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mergeRedirectURIs = %v, want %v", got, want)
	}
}

// oDataEscapeSingleQuote -----------------------------------------------------

func TestODataEscapeSingleQuote(t *testing.T) {
	tests := []struct{ in, want string }{
		{"amg", "amg"},
		{"it's", "it''s"},
		{"a'b'c", "a''b''c"},
		{"", ""},
	}
	for _, tt := range tests {
		got := oDataEscapeSingleQuote(tt.in)
		if got != tt.want {
			t.Errorf("oDataEscapeSingleQuote(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRun_AzNotInstalled(t *testing.T) {
	stub := &StubExecutor{
		LookPathFunc: func(name string) (string, error) { return "", errors.New("not found") },
	}
	opts := Options{
		InstanceName:   "amg",
		ExternalURL:    "https://example.com",
		NonInteractive: true,
		Exec:           stub,
		Stdout:         &strings.Builder{},
		Stderr:         &strings.Builder{},
	}
	err := Run(context.Background(), opts)
	if err == nil {
		t.Fatal("expected error when az is missing")
	}
	if !strings.Contains(err.Error(), "az") {
		t.Errorf("error should mention az; got: %v", err)
	}
}

func TestRun_InvalidInstanceName(t *testing.T) {
	stub := &StubExecutor{
		LookPathFunc: func(name string) (string, error) { return "/usr/bin/az", nil },
	}
	opts := Options{
		InstanceName:   "1bad",
		ExternalURL:    "https://example.com",
		NonInteractive: true,
		Exec:           stub,
		Stdout:         &strings.Builder{},
		Stderr:         &strings.Builder{},
	}
	err := Run(context.Background(), opts)
	if err == nil {
		t.Fatal("expected error for invalid instance name")
	}
}

// 修正2: GetTenantID が失敗しても Run がエラーを返さず、警告を出して続行すること
func TestRunEntraID_tenantIDFailure(t *testing.T) {
	stub := &StubExecutor{
		Responses: map[string]StubResponse{
			"az ad app list":             {Out: []byte(`[]`), Err: nil},
			"az ad app create":           {Out: []byte(`{"appId":"aid1","id":"oid1","displayName":"idproxy-amg"}`), Err: nil},
			"az ad app credential reset": {Out: []byte(`{"secretText":"s3cr3t"}`), Err: nil},
			"az ad app show":             {Out: []byte(`null`), Err: nil},
			"az ad app update":           {Out: []byte(`{}`), Err: nil},
			"az account show":            {Out: nil, Err: fmt.Errorf("not logged in")},
		},
	}
	var stderr strings.Builder
	opts := Options{
		InstanceName:   "amg",
		ExternalURL:    "https://example.com",
		NonInteractive: true,
		Exec:           stub,
		Stdout:         io.Discard,
		Stderr:         &stderr,
	}
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run() should succeed even when GetTenantID fails, got: %v", err)
	}
	if !strings.Contains(stderr.String(), "warning:") {
		t.Errorf("expected warning message in stderr, got: %q", stderr.String())
	}
}

// 修正3: secret 取得後にリダイレクト URI 設定で失敗した場合、PARTIAL SUCCESS を stderr に出力すること
func TestRunEntraID_partialSuccessOnRedirectURIFailure(t *testing.T) {
	stub := &StubExecutor{
		Responses: map[string]StubResponse{
			"az ad app list":             {Out: []byte(`[]`), Err: nil},
			"az ad app create":           {Out: []byte(`{"appId":"aid1","id":"oid1","displayName":"idproxy-amg"}`), Err: nil},
			"az ad app credential reset": {Out: []byte(`{"secretText":"s3cr3t"}`), Err: nil},
			// GetRedirectURIs で失敗させる（secret 取得後の後続ステップ失敗）
			"az ad app show": {Out: nil, Err: fmt.Errorf("network error")},
		},
	}
	var stderr strings.Builder
	opts := Options{
		InstanceName:   "amg",
		ExternalURL:    "https://example.com",
		NonInteractive: true,
		Exec:           stub,
		Stdout:         io.Discard,
		Stderr:         &stderr,
	}
	err := Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run() should return error when GetRedirectURIs fails")
	}
	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "[PARTIAL SUCCESS]") {
		t.Errorf("expected [PARTIAL SUCCESS] in stderr, got: %q", stderrStr)
	}
	if !strings.Contains(stderrStr, "OIDC_CLIENT_SECRET=s3cr3t") {
		t.Errorf("expected OIDC_CLIENT_SECRET=s3cr3t in stderr, got: %q", stderrStr)
	}
}
