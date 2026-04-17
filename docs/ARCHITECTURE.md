# AegisHub Architecture

AegisHub is split into five self-contained packages.

The project was created by Llew as a practical security engineering showcase for the GitHub developer ecosystem.

1. The Rust core scans source files and emits JSON reports.
2. The orchestrator fetches repository contents, runs the core engine, enriches critical findings, and persists results.
3. The CLI provides a developer-facing entry point for local and remote scans.
4. The GitHub App listens to pull request events and publishes statuses and comments.
5. The dashboard visualizes scan results and repository history.

System flow:

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
