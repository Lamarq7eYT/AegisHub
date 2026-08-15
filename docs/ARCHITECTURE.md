# AegisHub Architecture

AegisHub is split into focused packages with explicit ownership boundaries. The existing scanner path remains responsible for collecting source files, invoking the Rust engine and producing reports. Bounty Mode is an additional Phase 1 research workbench; it does not replace or silently alter the scanner.

## Existing product flow

1. The Rust core scans source files and emits JSON reports.
2. The orchestrator fetches repository contents, runs the core engine, enriches critical findings and persists results.
3. The CLI provides developer-facing entry points for local and remote scans.
4. The GitHub App listens to pull request events and publishes statuses and comments.
5. The dashboard visualizes scan results and repository history.

```text
GitHub Repo or Local Directory
        |
        v
 Orchestrator / CLI
        |
        v
 Rust Core Engine
        |
        v
 Findings + Score
        |
        +--> PostgreSQL
        +--> Dashboard
        +--> GitHub PR Status / Comment
```

## Bounty Mode ownership

`packages/bounty-core` contains pure contracts, the frozen Phase 1 catalog, policy rules, budgets, redaction, approval fingerprints, deterministic differential analysis and analysis-pack schemas. It must not perform network, filesystem or process I/O.

`packages/bounty-runtime` is the only Bounty Mode package that performs controlled GitHub and policy I/O. It owns Device Flow identity separation, session/keyring vaults, the fixed-path lab manifest, LabVerifier, policy snapshot/freshness checks, rate limiting, guarded transport, experiments, write-ahead cleanup journals, active-run leases, dirty-state recovery and atomic evidence bundles. Runtime operations are constrained by the catalog and by the verified lab snapshot.

`packages/cli` owns Commander registration, terminal presentation, readline confirmation and dependency composition. CLI code orchestrates injected runtime services; runtime modules do not import Commander, Chalk, Ora or readline. The default workspace is derived from `INIT_CWD` or the process directory, while local Bounty Mode state is kept under `.aegishub/` and never committed.

```text
CLI command tree
       |
       v
Injected Bounty services + terminal
       |
       v
bounty-runtime (controlled I/O)
       |
       +--> GitHub Device Flow / API through catalog transport
       +--> verified .aegishub lab and journals
       +--> sanitized evidence bundle
       |
       v
bounty-core (pure contracts, policy and analysis)
```

The ownership rule is intentionally strict: **only bounty-runtime performs GitHub or policy I/O**. Core and CLI do not make arbitrary network calls. All mutation-capable paths require an interactive terminal, a write-ahead journal, a verified inverse cleanup operation and a one-time approval grant. The Phase 1 bundled experiment itself is read-only and has a zero-mutation ceiling.

## Safety boundary

Identity records are separated by immutable GitHub ID, and the owner and researcher roles may not resolve to the same account. Experiment YAML cannot provide arbitrary URLs; it references only enumerated lab fields. The planner freezes a semantic plan fingerprint, and the runner revalidates policy, lab identity, budgets and the active lease immediately before work.

Observations are sanitized before they cross the evidence boundary. A candidate is a deterministic differential-analysis result for human review, not a severity assessment and never an automatic submission. The live integration test is opt-in and the normal CI path uses only loopback fixtures.

See [docs/BOUNTY_MODE.md](./BOUNTY_MODE.md) for operator procedures and [docs/superpowers/specs/2026-08-13-bounty-mode-foundation-design.md](./superpowers/specs/2026-08-13-bounty-mode-foundation-design.md) for the approved design.
