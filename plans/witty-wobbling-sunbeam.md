# CI/Release ワークフロー重複排除

## Context

現在 `release.yml` に `go vet` と `go test` のステップがあり、`ci.yml` のテスト・ビルドと重複している。
Release を CI の成功に依存させることで、重複を排除しつつリリースの安全性を保つ。

## 現状

- **ci.yml**: `push: branches: [main]` / `pull_request` でトリガー → test, lint, build ジョブ
- **release.yml**: `push: tags: ['v*']` でトリガー → go vet, go test, GoReleaser を1ジョブで実行

**問題**: タグpush時にCIが走らず、release.yml が独自にテストを実行している

## 変更内容

### 1. `ci.yml` — タグpushでもCIを実行

```yaml
on:
  push:
    branches: [main]
    tags: ['v*']        # ← 追加
  pull_request:
    branches: [main]
```

### 2. `release.yml` — `workflow_run` で CI 完了後に実行

```yaml
on:
  workflow_run:
    workflows: [CI]
    types: [completed]

jobs:
  release:
    if: >
      github.event.workflow_run.conclusion == 'success' &&
      startsWith(github.event.workflow_run.head_branch, 'v')
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
          ref: ${{ github.event.workflow_run.head_branch }}

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version-file: go.mod

      # go vet / go test は削除（CI で検証済み）

      - name: Generate GitHub App token
        id: app-token
        uses: tibdex/github-app-token@v2
        with:
          app_id: ${{ secrets.APP_ID }}
          private_key: ${{ secrets.APP_PRIVATE_KEY }}

      - name: Run GoReleaser
        uses: goreleaser/goreleaser-action@v6
        with:
          version: latest
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ github.token }}
          HOMEBREW_TAP_GITHUB_TOKEN: ${{ steps.app-token.outputs.token }}
```

**ポイント**:
- `workflow_run` はタグではなく「ブランチ名」として `head_branch` にタグ名が入る
- `startsWith(github.event.workflow_run.head_branch, 'v')` でタグpush時のみリリース実行
- `ref` にタグを指定してcheckoutすることでGoReleaserが正しくタグを認識
- `permissions: contents: write` は維持

## 対象ファイル

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`

## 検証

- タグなしのmain pushでCIのみ実行、Releaseは起動しないこと
- `v*` タグpushでCI → 成功後にReleaseが起動すること
- PRではCIのみ実行されること
