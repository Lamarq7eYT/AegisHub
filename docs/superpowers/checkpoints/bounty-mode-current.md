# AegisHub Bounty Mode Phase 1 — Current Checkpoint

## Branch and HEAD

- Branch: `codex/bounty-mode-foundation`
- HEAD: `77fca04745c7397ebbbb2ea04fa66b3c728ebba7`
- Commit: `feat(bounty): add deterministic safety and diff engines`
- Checkpoint timestamp: `2026-08-15T00:16:59Z` (2026-08-14 21:16:59, user timezone GMT-3)
- Worktree at checkpoint creation: clean; branch is ahead of `origin/codex/bounty-mode-foundation` by one commit.

## Audit before continuation

The requested branch existed remotely and was checked out without a reset. Its transferred HEAD was `ec7b85845d836643f45d8dccfbe570f8848c4acd`, `test(bounty): define policy snapshot review contracts`. No unrelated uncommitted user changes were present. The repository contained the approved design and implementation plan, the Task 1 strict contracts/stable JSON foundation, and the Task 2 pure policy engine plus partial runtime policy-source/snapshot work. No Task 3 production modules or tests existed before this continuation.

Tasks 0–2 were therefore treated as the repository baseline, with Task 3 Step 1 as the first incomplete step. The pure bounty-core Task 1–2 suite passed before Task 3 work: 59 tests in 2 files. The full monorepo baseline could not pass in this sandbox because `cargo` is unavailable; the runtime Task 2 suite also exposed pre-existing package-build/typecheck/lint gaps, including an unbuilt workspace package resolution failure and unimplemented snapshot/review seams. These were not silently attributed to Task 3 and remain known follow-up work.

## Tasks and Steps completed

- Task 0: repository state audited; locked dependency installation completed. The full pre-feature gate remains environment-blocked by missing Rust tooling and pre-existing runtime gaps.
- Task 1: present on the transferred branch; strict contracts and stable JSON were preserved.
- Task 2: present on the transferred branch; pure policy tests passed. Runtime policy implementation remains partially incomplete as noted above.
- Task 3: completed through Step 10 in this continuation.
  - Step 1–2: budget ceiling tests, property tests, ceiling validation, and atomic reservation.
  - Step 3–4: redaction property tests and run-local HMAC redactor with final scanner and destroy semantics.
  - Step 5–6: differential fixtures, deterministic normalization, repeat consistency, candidate gating, and fail-closed result classification.
  - Step 7: exact stable approval fingerprints and expiring single-use in-memory grants.
  - Step 8: dedicated sanitized analyst-observation schema and frozen analysis-pack builder.
  - Step 9: complete pure-package tests, lint, typecheck, and build.
  - Step 10: focused commit created as `77fca04`.

## Files created or modified by Task 3

Created:

- `packages/bounty-core/src/budget.ts`
- `packages/bounty-core/src/redaction.ts`
- `packages/bounty-core/src/differential.ts`
- `packages/bounty-core/src/approval.ts`
- `packages/bounty-core/src/analysis-pack.ts`
- `packages/bounty-core/test/budget.test.ts`
- `packages/bounty-core/test/redaction.property.test.ts`
- `packages/bounty-core/test/differential.test.ts`
- `packages/bounty-core/test/approval.test.ts`
- `packages/bounty-core/test/analysis-pack.test.ts`

Modified:

- `packages/bounty-core/src/contracts.ts`
- `packages/bounty-core/src/index.ts`
- `packages/bounty-core/test/contracts.test.ts`

The observation contract now explicitly stores `repeatGroup`, `protectedData`, `outOfLab`, and optional typed `errorClass`, matching the differential persistence requirements. The analyst boundary now uses a dedicated `analystObservationSchema` and does not accept methods, endpoint templates, request headers, raw bodies, credentials, executable code, or approval fields.

## Verification executed

The following pure-package checks passed after the final Task 3 changes:

- `pnpm --filter @aegishub/bounty-core test`: 7 test files, 126 tests passed.
- `pnpm --filter @aegishub/bounty-core typecheck`: passed.
- `pnpm --filter @aegishub/bounty-core lint`: passed with 12 existing/non-fatal security-rule warnings and no errors.
- `pnpm --filter @aegishub/bounty-core build`: passed; ESM and declaration output generated.
- `git diff --check`: passed before commit.

The focused Task 3 commit is:

```text
77fca04 feat(bounty): add deterministic safety and diff engines
```

## Security invariants preserved

The implementation keeps Phase 1 ceilings immutable, makes request and mutation reservations atomic, exposes no decrement operation, uses keyed run-local redaction placeholders, destroys the redaction key, rejects suspected secrets without echoing them, normalizes only fixed volatility, requires repeatable protected-data evidence and independent lab-owned impact for `anomalous`, prefers `inconclusive` for incomplete evidence, blocks policy/dirty/out-of-lab conditions, hashes the exact approval context, and consumes mutation grants once in memory.

The analyst pack is schema-first, recursively frozen, and contains only sanitized observations, evidence references, policy excerpt IDs, prior summaries, and existing catalog operation IDs. It cannot create an executable request or approval.

## Known problems and TODOs

Task 2 runtime policy snapshot loading, freshness monitoring, review transport, and atomic review script are now complete and verified. Runtime tests must first build `@aegishub/bounty-core` when run independently because the workspace package resolves through its built output. The monorepo baseline and final Rust gates still require Rust tooling (`cargo`) in the execution environment. Do not weaken the safety model or modify the Rust scanner casually.

Task 4 is complete. Authentication uses session-only credentials by default, explicit `persist: true` for vault storage, separate owner/researcher records, optional dynamically loaded keyring storage, strict GitHub App Device Flow mapping, immediate GET /user verification, immutable-ID separation, expiry deletion, logout, and local revocation. The optional native keyring remains external in the runtime bundle to avoid cross-platform native-binary resolution. Do not refactor or redo the correctly implemented Task 3 or Task 4 modules/tests. Do not change the Rust scanner, existing scan/report behavior, policy gating, catalog boundaries, or credential-storage rules.

## Next continuation point

Continue with **Task 12 — Step 1: implement the stateful loopback-only fake GitHub server**. Bind only to 127.0.0.1 on an ephemeral port, model the approved Device Flow/lab/transport faults, and then exercise the actual runtime end to end. The completed Task 11 commit is recorded below.

Before claiming Phase 1 completion, continue Task by Task through the remaining plan, keep this checkpoint current after every completed Task, run all non-live verification gates, and record the live gate as pending unless the user-owned lab is explicitly available and verified. Never request or store passwords, cookies, 2FA codes, access tokens, refresh tokens, or reserve-account credentials in chat or fixtures.

## Continuation update — 2026-08-15

New commits since the previous checkpoint:

- `fefe1f6 feat(bounty): complete reviewed policy runtime`
- `d82e143 feat(bounty): add separated Device Flow identities`
- `9589120 fix(bounty): require explicit credential persistence`

Verification after the update:

- bounty-core: 126 tests passed, typecheck passed, build passed.
- bounty-runtime: 145 tests passed, typecheck passed, lint passed with non-fatal security-rule warnings, build passed after externalizing the optional native keyring module.
- Task 4 focused auth gate: 20 tests passed and seeded token search in captured output returned zero matches.
- Worktree is clean at checkpoint creation; branch is ahead of origin by five commits.

## Continuation update — Task 5 completed

Task 5 is complete in commit `5be9209 feat(bounty): verify immutable owned-resource labs`. It adds fixed-path `.aegishub/bounty-lab.json` storage with stable hashes, atomic writes, restrictive permissions, symlink/traversal rejection, compare-and-swap replacement, immutable repository/owner verification, strict proof-of-control marker validation, explicit mutation confirmation, retained markers, rollback journaling, and dirty-state reporting without exposing control nonces.

Task 5 verification: runtime suite passed with 159 tests; runtime typecheck passed; runtime lint passed with zero errors and non-fatal security-rule warnings; runtime build passed with the optional keyring kept external. The worktree was clean after the Task 5 commit and the branch was ahead of origin by seven commits.

## Continuation update — Task 6 completed

Task 6 is complete in commit `797df47 feat(bounty): guard GitHub operations by catalog`. It adds the frozen Phase 1 operation catalog and fingerprint, strict parameter validation with fixed-origin URL rendering, runtime purpose/actor/repository guards, a per-run token bucket and semaphore, and a guarded transport with late authentication, fixed headers, redirect/manual credential controls, budgets, retries, stop conditions, byte caps, and sanitized observations.

Task 6 verification: bounty-core passed 131 tests, typecheck, lint with zero errors, and build. Bounty-runtime passed 171 tests, typecheck, lint with zero errors and non-fatal security warnings, and build. The worktree was clean after the Task 6 commit and the branch was ahead of origin by nine commits.

## Continuation update — Task 7 completed

Task 7 is complete in commit `c443aaf feat(bounty): plan declarative bounded experiments`. It adds bounded YAML/JSON experiment loading with a 64 KiB limit, strict schema validation, path and symlink guards, stable YAML/JSON hashing, immutable planning, policy/lab/catalog invariants, fixed phase ordering, explicit repeat requirements, and catalog-declared cleanup inverses. The frozen catalog now includes the marker cleanup inverse required by the planner.

Task 7 verification: bounty-runtime passed 187 tests, typecheck, lint with zero errors and non-fatal security-rule warnings, and build. Bounty-core build passed as the runtime dependency. `git diff --check` passed before commit. The worktree was clean at commit creation and the branch was ahead of origin by eleven commits.

## Continuation update — Task 8 completed

Task 8 is complete in commit `77cc9b8 feat(bounty): run experiments with verified cleanup`. It adds the append-only write-ahead mutation journal with fsync and hash links, state-machine transition validation, LabVerifier compatibility, exclusive active-run leases, cooperative emergency stop with run/nonce pairing, PID recovery, dirty-state persistence and verification-gated resolution, and the controlled ExperimentRunner with phase ordering, single-use approval consumption, policy/stop checks, lost-mutation verification, reverse cleanup, dirty marking, and differential classification.

Task 8 verification: bounty-core passed 131 tests, lint with zero errors and non-fatal security warnings, typecheck, and build. Bounty-runtime passed 204 tests across 16 files, lint with zero errors and non-fatal security warnings, typecheck, and build. The focused Task 8 suite passed 16 tests; `git diff --check` passed before commit. The worktree was clean at commit creation and the branch is ahead of origin by one commit.

## Continuation update — Task 9 completed

Task 9 is complete in commit `b2b11e4 feat(bounty): export sanitized evidence bundles`. It adds schema-first atomic evidence writing under `.aegishub/runs/<run-id>`, canonical JSON/NDJSON/Markdown layout, final secret scanning with run-local redaction, sorted SHA-256 checksums, overwrite and symlink guards, safe temporary-directory failure handling, verified inspect, deterministic reports and sanitized catalog-only reproduction instructions, plus atomic analysis-pack export validated by `analystInputSchema`.

Task 9 verification: bounty-core build passed. Bounty-runtime passed 204 tests across the existing suite plus 8 focused evidence/report tests, lint with zero errors and non-fatal security warnings, typecheck, and build. `git diff --check` passed before commit. The worktree was clean at commit creation and the branch is ahead of origin by one commit.

## Continuation update — Task 10 completed

Task 10 is complete in commit `be020d9 feat(bounty): add private contents boundary experiment`. It adds the strict bundled `repo.private.contents-read-boundary.v1` YAML, typed parameter references limited to the verified lab repository, built-in loading by fixed ID, planner resolution against immutable lab identity, the known-safe owner/researcher/anonymous read-only arrangement, stable semantic fingerprints, approval invalidation after semantic budget changes, and fail-closed scripted classifications for expected, precondition-not-met, anomalous, mixed and out-of-lab outcomes. The runtime build now copies the YAML into `dist/experiments`.

Task 10 verification: bounty-core passed 131 tests, lint with zero errors and non-fatal security warnings, typecheck and build. Bounty-runtime passed 216 tests across 19 files, lint with zero errors and non-fatal security warnings, typecheck and build; the focused bundled suite passed 4 tests. The built YAML asset was verified in `dist/experiments`, and `git diff --check` passed before commit. The worktree was clean at commit creation and the branch is ahead of origin by one commit.

## Continuation update — Task 11 completed

Task 11 is complete in commit `3412273 feat(cli): expose guarded bounty workflows`. It adds the nested `bounty` command tree, injected service composition root, session-only default and explicit keyring persistence selection, readline-based terminal confirmation, stable typed CLI errors, policy/auth/lab/experiment/run/evidence/stop orchestration, and two regression suites proving the legacy help/auth/report surface remains intact. The runtime YAML asset remains packaged for the CLI dependency.

Task 11 verification: focused CLI tests passed 10 tests; CLI lint passed with zero errors and one non-fatal filesystem-security warning; CLI typecheck and build passed. `git diff --check` passed before commit. The worktree was clean at commit creation and the branch is ahead of origin by one commit.

## Commands to resume

```bash
cd /home/ubuntu/AegisHub
git switch codex/bounty-mode-foundation
pnpm install --frozen-lockfile
pnpm --filter @aegishub/bounty-core test
pnpm --filter @aegishub/bounty-core lint
pnpm --filter @aegishub/bounty-core typecheck
pnpm --filter @aegishub/bounty-core build
```
