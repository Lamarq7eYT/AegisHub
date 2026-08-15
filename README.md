# AegisHub

Security feedback for GitHub repositories before risky code reaches production.

![AegisHub demo](./docs/assets/aegishub-demo.gif)

AegisHub is a modular GitHub security analyzer built for everyday developers. It scans source code, detects exposed secrets and unsafe patterns, produces a numeric security score, and presents findings in a visual dashboard with actionable fix suggestions.

## Built By

AegisHub was created by **Llew** with a lot of effort, focus, and dedication. It is a portfolio project made to show practical security engineering, product thinking, GitHub workflow awareness, and the ability to turn an ambitious idea into a working developer tool.

## What Works Today

- A Rust security engine with a typed `Analyzer` trait.
- A working `SecretsAnalyzer` with pattern and entropy detection.
- Native JSON engine output through `aegishub-engine`.
- A CLI that can scan local folders and GitHub repositories.
- A polished React dashboard demo with realistic scan data.
- Automated demo capture that generates README-ready GIF and screenshots.

## Quick Start

Install dependencies:

```bash
pnpm install
```

Run the dashboard demo:

```bash
pnpm --filter @aegishub/dashboard dev
```

Run all checks:

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

## Scan Any Local Repository

Build the CLI:

```bash
pnpm --filter aegishub build
```

Scan this repository:

```bash
pnpm --filter aegishub scan -- .
```

Scan another local project:

```bash
pnpm --filter aegishub scan -- ../some-project
```

The CLI prints a terminal summary and writes the full JSON report to:

```text
aegishub-report.json
```

## Scan A GitHub Repository

Scan a public repository by shorthand:

```bash
pnpm --filter aegishub scan -- owner/repo
```

Or by URL:

```bash
pnpm --filter aegishub scan -- https://github.com/owner/repo
```

Use a specific branch, tag, or commit:

```bash
pnpm --filter aegishub scan -- owner/repo --ref main
```

Private repositories and higher GitHub API limits require `GITHUB_TOKEN`:

```bash
export GITHUB_TOKEN="your_token_here"
```

PowerShell:

```powershell
$env:GITHUB_TOKEN="your_token_here"
```

No real credentials are included in this repository.

## Bounty Mode Phase 1

Bounty Mode is a safety-constrained security research workbench for a verified, directly owner-owned private lab. It uses separate Device Flow identities, fixed catalog operations, low-volume budgets, policy and lab verification, deterministic differential analysis, write-ahead cleanup journaling and sanitized evidence. It is **not an autonomous bounty finder**, does not enumerate third-party targets and never submits reports.

Read the complete [Bounty Mode operator guide](./docs/BOUNTY_MODE.md) before enabling any workflow. The normal suite is loopback-only; live GitHub validation is opt-in and requires the user present with an already enrolled owned lab.

```bash
pnpm --filter aegishub build
node packages/cli/dist/index.js bounty --help
node packages/cli/dist/index.js bounty experiment list
```

## What It Detects

- Exposed credentials and API keys.
- High-entropy string literals that may contain secrets.
- Unsafe execution patterns such as dynamic code evaluation.
- SQL injection patterns in raw query construction.
- Risky file path handling and other hardening opportunities.

The first implemented engine milestone is `packages/core`, which includes the Rust analyzer trait, `SecretsAnalyzer`, score computation, JSON report output, and tests. The dashboard demo already shows the broader product direction while the remaining analyzers and backend pipeline are being implemented.

## How It Works

```text
Local directory or GitHub repository
        |
        v
 AegisHub CLI / Orchestrator
        |
        v
 Rust core engine
        |
        v
 Findings and score
        |
        +--> Terminal report
        +--> JSON report
        +--> Dashboard
        +--> Future GitHub PR status and comment
```

For the current CLI flow:

1. The CLI collects text source files.
2. It skips generated folders, binaries, large files, dependency folders, and minified JavaScript.
3. It sends a JSON payload to the Rust engine.
4. The engine runs analyzers and computes a score from 0 to 100.
5. The CLI prints a readable summary and saves the full report.

## Demo Assets

The demo is designed for GitHub community submissions and recruiter review.

```bash
pnpm capture:demo
```

Generated assets:

- [Demo GIF](./docs/assets/aegishub-demo.gif)
- [Demo WebM](./docs/assets/aegishub-demo.webm)
- [Dashboard screenshot](./docs/assets/dashboard-preview.png)
- [Expanded finding screenshot](./docs/assets/dashboard-finding-expanded.png)
- [SVG preview](./docs/assets/aegishub-preview.svg)

For recording notes, see [docs/DEMO.md](./docs/DEMO.md).

## Packages

- `packages/core` - Rust analysis engine with native and WASM targets.
- `packages/orchestrator` - Fastify backend for scan orchestration, persistence, and AI enrichment.
- `packages/cli` - Developer CLI for local and remote scans plus guarded Bounty Mode orchestration.
- `packages/bounty-core` - Pure Bounty Mode contracts, policy, catalog, budgets, redaction and differential analysis.
- `packages/bounty-runtime` - Controlled Bounty Mode auth, lab, transport, runner, evidence and integration harness.
- `packages/github-app` - GitHub App webhook handler and PR notifier.
- `packages/dashboard` - React and Vite dashboard for scan reports.

## Architecture

More detail is available in [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md). Bounty Mode ownership and safety boundaries are described in [docs/BOUNTY_MODE.md](./docs/BOUNTY_MODE.md).

## Roadmap

- Complete `UnsafeCodeAnalyzer`.
- Add AST-backed SQL injection analysis.
- Implement repository fetching and scan queue in the orchestrator.
- Add GitHub App PR status and comment publishing.
- Connect AI fix generation with cache-backed enrichment.
- Add dependency audit through OSV.
- Continue Bounty Mode only through verified owned-lab experiments, non-live CI and an explicit human review gate.

## Security

Please do not report sensitive vulnerabilities through public issues. See [docs/SECURITY.md](./docs/SECURITY.md).
