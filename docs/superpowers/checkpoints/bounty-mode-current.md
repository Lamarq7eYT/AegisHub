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

Continue with **Task 6 — Step 1: write catalog escape and fingerprint property tests**. Implement the reviewed operation catalog, deterministic rate limiter, and guarded GitHub transport only after observing their focused RED states. The next intended commit from the plan is:

```text
feat(bounty): guard GitHub operations by catalog
```

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
