# GoReleaser Homebrew Tap + GitHub Apps トークン設定

## Context

board リポジトリと同様に、idproxy でも goreleaser で Homebrew tap (`youyo/homebrew-tap`) に Formula を自動公開したい。
そのために GitHub Apps トークンを生成し、goreleaser に `HOMEBREW_TAP_GITHUB_TOKEN` として渡す必要がある。
secrets (`APP_ID`, `APP_PRIVATE_KEY`) はユーザーが設定済み。

## 変更ファイル

### 1. `.github/workflows/release.yml`

board / logvalet の release.yml を参考に以下を変更:

- ステップに name を追加（可読性向上）
- `tibdex/github-app-token@v2` による GitHub App トークン生成ステップを追加
- goreleaser ステップに `HOMEBREW_TAP_GITHUB_TOKEN` 環境変数を追加
- `GITHUB_TOKEN` を `${{ github.token }}` に変更（logvalet/board と統一）
- board と同様、`go vet` / `go test` ステップを追加（リリース前の最終検証）

### 2. `.goreleaser.yml`

board の `.goreleaser.yaml` を参考に `brews` セクションを追加:

```yaml
brews:
  - name: idproxy
    repository:
      owner: youyo
      name: homebrew-tap
      token: "{{ .Env.HOMEBREW_TAP_GITHUB_TOKEN }}"
    directory: Formula
    homepage: "https://github.com/youyo/idproxy"
    description: "idproxy - Identity-aware reverse proxy with OAuth 2.1"
    license: "MIT"
    install: |
      bin.install "idproxy"
    test: |
      system "#{bin}/idproxy", "--help"
```

## 検証

- `goreleaser check` で設定ファイルの構文検証
- workflow ファイルの YAML 構文確認
