# Pull Request Summary Report

Use this checklist when AegisHub posts scanner results back to a pull request.
It keeps the signal short enough for reviewers while preserving links to full
artifacts.

## Summary Block

- Scan status: passed, warnings, or failed.
- Files scanned: total files, skipped files, and skip reasons.
- Findings by severity: critical, high, medium, low, and informational.
- Changed files with findings: only paths touched by the pull request.
- Artifact links: JSON report, SARIF report, and dashboard snapshot.

## Reviewer Flow

1. Read the severity summary first.
2. Open only findings attached to changed files.
3. Confirm whether every high or critical finding has a decision.
4. Leave low confidence findings as advisory notes instead of merge blockers.

## Merge Gate

A pull request should be blocked when a high confidence critical finding is
introduced by the change and no override note is present. Medium and low
findings should stay visible in the report without hiding the final merge
decision.
