# aegishub CLI

Developer-facing command line interface for scanning local directories and GitHub repositories.

## Usage

From the monorepo:

```bash
pnpm --filter aegishub build
pnpm --filter aegishub scan -- .
```

Scan a different local repository:

```bash
pnpm --filter aegishub scan -- ../some-project
```

Scan a public GitHub repository:

```bash
pnpm --filter aegishub scan -- owner/repo
pnpm --filter aegishub scan -- https://github.com/owner/repo
```

Private repositories and higher GitHub API limits require a token:

```bash
export GITHUB_TOKEN="your_token_here"
```

PowerShell:

```powershell
$env:GITHUB_TOKEN="your_token_here"
```

## Commands

- `aegishub scan [target]` - scan a local directory, GitHub URL, or `owner/repo`.
- `aegishub report [path]` - print a saved JSON report.
- `aegishub auth` - show GitHub token setup instructions.

## Output

The CLI prints a concise terminal report and writes the full JSON report to `aegishub-report.json`.

## Notes

This initial CLI shells out to the Rust engine in `packages/core`, which keeps the analyzer implementation centralized while the npm packaging story evolves.
