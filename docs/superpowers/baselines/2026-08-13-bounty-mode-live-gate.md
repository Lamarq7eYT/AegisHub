# Bounty Mode Phase 1 — Live Gate Baseline

**Status:** Passed with user present

The user-present live gate completed on 2026-08-15 with the configured public GitHub App client ID, two fresh in-process Device Flow authorizations, the current reviewed policy snapshot, the directly owner-owned private lab repository, a verified lab marker, an interactive TTY assertion, and explicit user confirmation of the repository matrícula. No password, cookie, two-factor code, access token, refresh token, reserve-account credential, or other secret was sent in chat or stored in fixtures.

## Recorded run

| Field | Value |
| --- | --- |
| Run ID | `352ce099-428a-4fa1-b353-71aafd0a0734` |
| Result | `expected` |
| Experiment | `repo.private.contents-read-boundary.v1` |
| Request count | `10` |
| Mutation count | `0` |
| Cleanup status | `not-required` |
| Evidence bundle | `/home/ubuntu/AegisHub/.aegishub/runs/352ce099-428a-4fa1-b353-71aafd0a0734` |

The boundary assertions passed: owner observations succeeded, researcher and anonymous observations were denied with the expected `403`/`404` statuses, the owner repeat remained successful, no candidate was produced, and the classified result was `expected`.

## Evidence verification

`AtomicEvidenceWriter.inspect()` returned `verified: true`. The bundle passed schema validation, checksum verification, redaction checks, and the absence-of-secret assertions. The recorded checksum file contains the eight sanitized evidence files: `diff.json`, `experiment.json`, `manifest.json`, `observations.ndjson`, `plan.json`, `policy.json`, `report.md`, and `reproduce.md`.

## Reproduction command

The live test remains opt-in and is skipped by normal non-live runs:

```bash
AEGISHUB_BOUNTY_LIVE=1 pnpm --filter @aegishub/bounty-runtime test:live
```

The test file is `packages/bounty-runtime/test/live/private-boundary.live.test.ts`. Normal CI and non-live test runs keep `AEGISHUB_BOUNTY_LIVE=0` or unset, so they do not contact GitHub or prompt for interactive authorization.

This baseline records the completed gate only. It does not authorize arbitrary targets, increase immutable Phase 1 ceilings, permit unattended mutations, or change the rule that `anomalous` means candidate for human review rather than automatic submission.
