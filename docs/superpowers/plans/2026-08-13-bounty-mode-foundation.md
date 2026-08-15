# AegisHub Bounty Mode Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the approved Phase 1 Bounty Mode foundation to AegisHub: two-account Device Flow authentication, verified owned-resource labs, policy-gated low-volume experiments, deterministic differential analysis, cleanup safety, and sanitized proof-of-concept evidence, while preserving the current Rust scanner and CLI commands.

**Architecture:** Keep the Rust scanner unchanged. Add a pure `@aegishub/bounty-core` package for schemas and deterministic decisions, an I/O-only `@aegishub/bounty-runtime` package for authentication, GitHub transport, lab state, execution, and evidence writing, then register a thin `bounty` command tree in the existing CLI. Every network action resolves a reviewed operation ID; every active repository resolves to a manifest-pinned immutable ID; every persisted byte passes redaction.

**Tech Stack:** Node.js 20, TypeScript 5.7 with strict settings, pnpm 9.15.4/Turbo, Zod 3.24, Vitest 4, fast-check 4, YAML 2, Octokit Device OAuth, optional `@napi-rs/keyring`, native `fetch`/`node:http`, SHA-256/HMAC from `node:crypto`.

## Global Constraints

- Work only on `codex/bounty-mode-foundation`. Preserve the approved design commit and all unrelated user changes.
- Follow test-driven development: add one focused failing test, observe the expected failure, add the minimum implementation, observe the pass, then refactor.
- Before diagnosing any unexpected failure, invoke `superpowers:systematic-debugging`. Before claiming completion, invoke `superpowers:verification-before-completion`.
- Do not contact GitHub production from normal tests or CI. Fixtures contain synthetic identities, repositories, content, and token-shaped strings only.
- Do not change `packages/core`, `packages/orchestrator`, `packages/github-app`, or `packages/dashboard` unless a demonstrated compatibility defect makes a narrowly scoped change necessary.
- Preserve the behavior of `aegishub scan`, `aegishub report`, and the existing top-level `aegishub auth` command.
- Production REST operations use only `https://api.github.com`. Device Flow uses only `https://github.com/login/device/code` and `https://github.com/login/oauth/access_token`. Policy checks use only the five reviewed `https://bounty.github.com` pages.
- No arbitrary URL, method, header, GraphQL text, shell command, JavaScript callback, or redirect can originate in an experiment file.
- Default ceilings are immutable in Phase 1: concurrency `1`, sustained rate `1 request/second`, burst `2`, requests `100`, mutations `10`, timeout `20_000 ms`, safe-read retries `2`, automatic mutation retries `0`.
- The CLI may lower a budget only through a validated experiment. It exposes no flag that raises a ceiling.
- Mutations require a terminal attached to the process, an in-memory one-run approval matching the exact plan fingerprint, and a write-ahead cleanup journal. `--yes` and non-interactive mutation execution are rejected.
- Session-only authentication is the default. `--persist` is optional and must use the OS keychain; plaintext fallback is forbidden.
- Starting Device Flow requires an interactive terminal so its short-lived user code cannot be redirected into a file or non-interactive log.
- Phase 1 does not refresh an expired GitHub App user token. GitHub requires a client secret for refresh, while the approved Device Flow setup intentionally uses only a client ID. The authentication module detects expiry, removes the unusable record, and starts a new Device Flow. No other module handles token lifecycle.
- The optional organization fields remain schema-compatible, but enrollment must fail closed unless organization-owner status can be proven with the exact approved permissions. With the Phase 1 no-organization-permission App configuration, the supported live lab is a repository directly owned by the `owner` account.
- `anomalous` means “candidate for human review,” never “confirmed vulnerability,” and the system never submits or publishes a report.

## Exact Dependency Set

Add only these direct dependencies for the new packages:

| Package | Runtime dependencies | Development dependencies |
|---|---|---|
| `@aegishub/bounty-core` | `zod@^3.24.1` | `fast-check@^4.9.0`, `tsup@^8.3.5`, `vitest@^4.1.5` |
| `@aegishub/bounty-runtime` | `@aegishub/bounty-core@workspace:*`, `@octokit/auth-oauth-device@^8.0.4`, `@octokit/request@^10.0.13`, `yaml@^2.9.0`, `zod@^3.24.1` | `fast-check@^4.9.0`, `tsx@^4.19.2`, `tsup@^8.3.5`, `vitest@^4.1.5` |
| `@aegishub/bounty-runtime` optional | `@napi-rs/keyring@^1.3.0` | none |
| `aegishub` | `@aegishub/bounty-core@workspace:*`, `@aegishub/bounty-runtime@workspace:*` | existing dependencies |

Do not add a general HTTP client, browser automation library, HTML parser, prompt framework, database, queue, or AI SDK in Phase 1.

## File Map

### Repository root and documentation

- Modify: `.gitignore`
- Create: `.env.example`
- Modify: `README.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/SECURITY.md`
- Create: `docs/BOUNTY_MODE.md`
- Modify mechanically: `pnpm-lock.yaml`
- Modify: `.github/workflows/ci.yml`

### Pure package: `packages/bounty-core`

- Create: `packages/bounty-core/package.json`
- Create: `packages/bounty-core/tsconfig.json`
- Create: `packages/bounty-core/src/index.ts`
- Create: `packages/bounty-core/src/contracts.ts`
- Create: `packages/bounty-core/src/stable-json.ts`
- Create: `packages/bounty-core/src/budget.ts`
- Create: `packages/bounty-core/src/policy.ts`
- Create: `packages/bounty-core/src/catalog.ts`
- Create: `packages/bounty-core/src/redaction.ts`
- Create: `packages/bounty-core/src/differential.ts`
- Create: `packages/bounty-core/src/approval.ts`
- Create: `packages/bounty-core/src/analysis-pack.ts`
- Create: `packages/bounty-core/test/contracts.test.ts`
- Create: `packages/bounty-core/test/budget.test.ts`
- Create: `packages/bounty-core/test/policy.test.ts`
- Create: `packages/bounty-core/test/catalog.property.test.ts`
- Create: `packages/bounty-core/test/redaction.property.test.ts`
- Create: `packages/bounty-core/test/differential.test.ts`
- Create: `packages/bounty-core/test/approval.test.ts`
- Create: `packages/bounty-core/test/analysis-pack.test.ts`

### Controlled-I/O package: `packages/bounty-runtime`

- Create: `packages/bounty-runtime/package.json`
- Create: `packages/bounty-runtime/tsconfig.json`
- Create: `packages/bounty-runtime/src/index.ts`
- Create: `packages/bounty-runtime/src/paths.ts`
- Create: `packages/bounty-runtime/src/auth/vault.ts`
- Create: `packages/bounty-runtime/src/auth/device-flow.ts`
- Create: `packages/bounty-runtime/src/auth/identity-manager.ts`
- Create: `packages/bounty-runtime/src/lab/store.ts`
- Create: `packages/bounty-runtime/src/lab/verifier.ts`
- Create: `packages/bounty-runtime/src/policy/source-client.ts`
- Create: `packages/bounty-runtime/src/policy/snapshot.ts`
- Create: `packages/bounty-runtime/src/transport/operation-catalog.ts`
- Create: `packages/bounty-runtime/src/transport/rate-limiter.ts`
- Create: `packages/bounty-runtime/src/transport/guarded-transport.ts`
- Create: `packages/bounty-runtime/src/experiments/loader.ts`
- Create: `packages/bounty-runtime/src/experiments/planner.ts`
- Create: `packages/bounty-runtime/src/experiments/journal.ts`
- Create: `packages/bounty-runtime/src/experiments/active-run.ts`
- Create: `packages/bounty-runtime/src/experiments/runner.ts`
- Create: `packages/bounty-runtime/src/evidence/writer.ts`
- Create: `packages/bounty-runtime/src/evidence/report.ts`
- Create: `packages/bounty-runtime/policy/github-bug-bounty.v1.json`
- Create: `packages/bounty-runtime/experiments/repo.private.contents-read-boundary.v1.yaml`
- Create: `packages/bounty-runtime/scripts/review-policy.ts`
- Create: `packages/bounty-runtime/test/support/fake-github-server.ts`
- Create focused tests beside the corresponding runtime area under `packages/bounty-runtime/test/`.
- Create: `packages/bounty-runtime/test/live/private-boundary.live.test.ts`

### Existing CLI

- Modify: `packages/cli/package.json`
- Modify: `packages/cli/src/index.ts`
- Create: `packages/cli/src/bounty/register-bounty-command.ts`
- Create: `packages/cli/src/bounty/services.ts`
- Create: `packages/cli/src/bounty/terminal.ts`
- Create: `packages/cli/test/bounty-command.test.ts`
- Create: `packages/cli/test/existing-command-regression.test.ts`

## Stable Public Interfaces

Implement against these interfaces; do not let later tasks invent parallel shapes:

```ts
export type Actor = 'owner' | 'researcher' | 'anonymous';
export type AuthenticatedActor = Exclude<Actor, 'anonymous'>;
export type PolicyState = 'current' | 'fresh-unverified' | 'stale' | 'review-required';
export type RunResultState =
  | 'expected'
  | 'anomalous'
  | 'inconclusive'
  | 'policy_blocked'
  | 'dirty';

export interface CredentialVault {
  capability(): Promise<'session' | 'keychain'>;
  get(actor: AuthenticatedActor): Promise<CredentialRecord | undefined>;
  set(actor: AuthenticatedActor, record: CredentialRecord): Promise<void>;
  delete(actor: AuthenticatedActor): Promise<void>;
  clear(): Promise<void>;
}

export interface TokenProvider {
  getUsableToken(actor: AuthenticatedActor): Promise<string>;
}

export interface GitHubOperationExecutor {
  execute(request: PlannedOperation, signal: AbortSignal): Promise<Observation>;
}

export interface AnalystAdapter {
  analyze(input: AnalystInput): Promise<AnalystOutput>;
}
```

`CredentialRecord` is runtime-internal and must never be accepted by evidence or analyst schemas. `PlannedOperation` contains a catalog ID and validated parameters, not a raw URL. `Observation` contains sanitized normalized data plus a raw-body SHA-256, never a raw body or authorization header.

---

## Task 0: Establish and Record the Baseline

**Files:**

- Read: `package.json`
- Read: `pnpm-lock.yaml`
- Read: `packages/cli/src/index.ts`
- Read: `packages/core/Cargo.toml`
- Create only if a failure exists before feature work: `docs/superpowers/baselines/2026-08-13-bounty-mode-baseline.md`

- [ ] **Step 1: Confirm branch and cleanliness**

Run:

```bash
git branch --show-current
git status --short
git log -3 --oneline
```

Expected: branch is `codex/bounty-mode-foundation` and commit `2def67b` is present. Preserve any unrelated changes; do not reset them.

- [ ] **Step 2: Install exactly the locked baseline**

Run:

```bash
pnpm install --frozen-lockfile
```

Expected: exit `0` with no lockfile change.

- [ ] **Step 3: Run the pre-feature gate**

Run:

```bash
pnpm lint
pnpm typecheck
cargo test --manifest-path packages/core/Cargo.toml
pnpm test
pnpm build
```

Expected: all exit `0`. If anything fails, record the command, exit status, and relevant output in the baseline file, invoke systematic debugging, and separate any baseline fix from Bounty Mode work.

- [ ] **Step 4: Record the baseline result**

No commit is needed when the baseline passes without changes. If a baseline defect exists, stop this feature plan, record it in `docs/superpowers/baselines/2026-08-13-bounty-mode-baseline.md`, and obtain approval for a separate exact fix plan before continuing.

## Task 1: Scaffold Both Packages and Lock the Domain Contracts

**Files:**

- Create: `packages/bounty-core/package.json`
- Create: `packages/bounty-core/tsconfig.json`
- Create: `packages/bounty-core/src/contracts.ts`
- Create: `packages/bounty-core/src/stable-json.ts`
- Create: `packages/bounty-core/src/index.ts`
- Create: `packages/bounty-core/test/contracts.test.ts`
- Create: `packages/bounty-runtime/package.json`
- Create: `packages/bounty-runtime/tsconfig.json`
- Create: `packages/bounty-runtime/src/paths.ts`
- Create: `packages/bounty-runtime/src/index.ts`
- Modify: `pnpm-lock.yaml`

- [ ] **Step 1: Add package manifests and TypeScript configurations**

Use these exact package manifests:

```json
{
  "name": "@aegishub/bounty-core",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "import": "./dist/index.js"
    }
  },
  "scripts": {
    "build": "tsup src/index.ts --format esm --dts --clean",
    "lint": "eslint src test scripts --ext .ts --no-error-on-unmatched-pattern",
    "test": "vitest run --passWithNoTests",
    "typecheck": "tsc -p tsconfig.json --noEmit"
  },
  "dependencies": {
    "zod": "^3.24.1"
  },
  "devDependencies": {
    "fast-check": "^4.9.0",
    "tsup": "^8.3.5",
    "vitest": "^4.1.5"
  }
}
```

```json
{
  "name": "@aegishub/bounty-runtime",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "import": "./dist/index.js"
    }
  },
  "scripts": {
    "build": "tsup src/index.ts --format esm --dts --clean",
    "lint": "eslint src test scripts --ext .ts --no-error-on-unmatched-pattern",
    "test": "vitest run --passWithNoTests",
    "typecheck": "tsc -p tsconfig.json --noEmit"
  },
  "dependencies": {
    "@aegishub/bounty-core": "workspace:*",
    "@octokit/auth-oauth-device": "^8.0.4",
    "@octokit/request": "^10.0.13",
    "yaml": "^2.9.0",
    "zod": "^3.24.1"
  },
  "optionalDependencies": {
    "@napi-rs/keyring": "^1.3.0"
  },
  "devDependencies": {
    "fast-check": "^4.9.0",
    "tsx": "^4.19.2",
    "tsup": "^8.3.5",
    "vitest": "^4.1.5"
  }
}
```

Use `rootDir: "."` and include `src/**/*.ts`, `test/**/*.ts`, and `scripts/**/*.ts` so tests and scripts are typechecked. Keep `module: "ESNext"` and `moduleResolution: "Bundler"` from the root config; TypeScript 5.7 resolves Octokit's conditional exports in this configuration.

For `packages/bounty-runtime/src/paths.ts`, derive the package root identically from unbundled `src` and bundled `dist`:

```ts
import { fileURLToPath } from 'node:url';

export const bountyRuntimeRoot = fileURLToPath(new URL('..', import.meta.url));
```

- [ ] **Step 2: Write the failing strict-contract tests**

Create tests that assert:

1. Unknown fields fail on the lab manifest, marker, policy snapshot, experiment, observation, candidate, and analyst input/output.
2. `owner`, `researcher`, and `anonymous` are the only actor values.
3. GitHub IDs are positive safe integers, node IDs and logins are non-empty, and the host is literally `github.com`.
4. Repository full names have exactly one slash and match the separately stored owner/name.
5. Experiment phases contain only typed operation steps.
6. JSON evidence values reject `undefined`, functions, symbols, non-finite numbers, and class instances.

The first test should be concrete:

```ts
import { describe, expect, it } from 'vitest';
import { labManifestSchema } from '../src/contracts.js';

describe('labManifestSchema', () => {
  it('rejects an unknown safety setting', () => {
    const result = labManifestSchema.safeParse({
      schemaVersion: 1,
      labId: '95f38cca-42e2-4b7d-82e6-f13f4549b2f3',
      githubHost: 'github.com',
      owner: { id: 1001, nodeId: 'U_owner', login: 'owner-fixture' },
      researcher: { id: 2002, nodeId: 'U_researcher', login: 'researcher-fixture' },
      repositories: [],
      approvedOperationFamilies: ['repository-read-boundary'],
      budgets: {
        concurrency: 1,
        requestsPerSecond: 1,
        burst: 2,
        maxRequests: 100,
        maxMutations: 10,
        timeoutMs: 20_000,
        maxReadRetries: 2,
        maxMutationRetries: 0
      },
      retention: { maxResponseBytes: 262_144, keepRuns: 20 },
      createdAt: '2026-08-13T12:00:00.000Z',
      verifiedAt: '2026-08-13T12:00:00.000Z',
      allowArbitraryHosts: true
    });

    expect(result.success).toBe(false);
  });
});
```

- [ ] **Step 3: Run the focused test and observe RED**

Run:

```bash
pnpm --filter @aegishub/bounty-core exec vitest run test/contracts.test.ts
```

Expected: FAIL because `contracts.ts` does not yet export the schema.

- [ ] **Step 4: Implement strict, versioned schemas**

In `contracts.ts`, define and export:

- `actorSchema` and `authenticatedActorSchema`.
- `githubIdentitySchema`.
- `budgetSchema` and `retentionSchema`.
- `labRepositorySchema`, `labManifestSchema`, and `repositoryMarkerSchema`.
- `policySnapshotSchema` and `policyStatusSchema`.
- `operationIdSchema`, `operationStepSchema`, `experimentSchema`, and `plannedOperationSchema`.
- `observationSchema`, `diffSchema`, `candidateSchema`, `runManifestSchema`, and `evidenceIndexSchema`.
- `analystInputSchema` and `analystOutputSchema`.
- inferred exported TypeScript types for each schema.

Every object schema ends with `.strict()`. Use discriminated unions for:

```ts
export const operationStepSchema = z.discriminatedUnion('phase', [
  baseStepSchema.extend({ phase: z.literal('setup') }).strict(),
  baseStepSchema.extend({ phase: z.literal('baseline') }).strict(),
  baseStepSchema.extend({ phase: z.literal('probe') }).strict(),
  baseStepSchema.extend({ phase: z.literal('verify') }).strict(),
  baseStepSchema.extend({ phase: z.literal('repeat') }).strict(),
  baseStepSchema.extend({ phase: z.literal('cleanup') }).strict()
]);

export const boundaryExpectationSchema = z
  .object({
    kind: z.literal('access-boundary'),
    ownerSuccessStatuses: z.array(z.number().int()).min(1),
    untrustedDeniedStatuses: z.array(z.number().int()).min(1),
    protectedFields: z.array(z.string().min(1)).min(1),
    requireOwnerRepeat: z.literal(true),
    minimumConsistentUntrustedAttempts: z.number().int().min(2).max(3)
  })
  .strict();
```

Define `JsonValue` recursively and validate it. Do not use `z.any()`. Operation parameters use `z.record(z.string(), jsonValueSchema)` only as the serialized envelope; the catalog applies a second operation-specific strict schema before planning.

In `stable-json.ts`, recursively sort object keys, preserve array order, reject unsupported values, and expose:

```ts
export function stableJson(value: JsonValue): string;
export function sha256StableJson(value: JsonValue): string;
```

- [ ] **Step 5: Add contract round-trip and stable-JSON tests**

Assert parse → serialize → parse equality for one complete lab, experiment, observation, and evidence manifest. Assert differently ordered object keys have the same stable hash while differently ordered arrays do not.

- [ ] **Step 6: Run package checks and observe GREEN**

Run:

```bash
pnpm install
pnpm --filter @aegishub/bounty-core lint
pnpm --filter @aegishub/bounty-core typecheck
pnpm --filter @aegishub/bounty-core test
pnpm --filter @aegishub/bounty-core build
pnpm --filter @aegishub/bounty-runtime typecheck
```

Expected: all exit `0`; `pnpm-lock.yaml` contains only the declared dependency graph.

- [ ] **Step 7: Commit the package and contract foundation**

```bash
git add packages/bounty-core packages/bounty-runtime/package.json packages/bounty-runtime/tsconfig.json packages/bounty-runtime/src/index.ts packages/bounty-runtime/src/paths.ts pnpm-lock.yaml
git commit -m "feat(bounty): add strict phase one contracts"
```

## Task 2: Implement the Reviewed Policy Snapshot and Freshness Gate

**Files:**

- Create: `packages/bounty-core/src/policy.ts`
- Modify: `packages/bounty-core/src/index.ts`
- Create: `packages/bounty-core/test/policy.test.ts`
- Create: `packages/bounty-runtime/src/policy/source-client.ts`
- Create: `packages/bounty-runtime/src/policy/snapshot.ts`
- Create: `packages/bounty-runtime/policy/github-bug-bounty.v1.json`
- Create: `packages/bounty-runtime/scripts/review-policy.ts`
- Create: `packages/bounty-runtime/test/policy-source.test.ts`

- [ ] **Step 1: Write freshness-state and policy-gate tests**

Cover this exact truth table with an injected clock:

| Source result | Snapshot age | Expected state |
|---|---:|---|
| all five normalized hashes match | any | `current` |
| at least one normalized hash differs | any | `review-required` |
| network failure and reviewed 30 days ago or less | ≤ 30 days | `fresh-unverified` |
| network failure and reviewed more than 30 days ago | > 30 days | `stale` |
| malformed snapshot or unreviewed enforcement | any | reject before state |

Also assert:

- `current` permits read-only and mutating plans within policy.
- `fresh-unverified` permits only read-only plans and emits a warning code.
- `stale` and `review-required` block every active plan.
- Every permanently forbidden class is rejected even when status is `current`.
- A policy fingerprint changes if a source hash, enforcement rule, or policy version changes.

Use named reason codes, not message matching:

```ts
expect(
  evaluatePolicyGate({
    status: { state: 'fresh-unverified', checkedAt: now, sourceResults: [] },
    mutationCount: 1,
    targets: ['api.github.com'],
    operationFamilies: ['repository-read-boundary']
  })
).toEqual({
  allowed: false,
  reason: 'mutation_requires_current_policy'
});
```

- [ ] **Step 2: Run the tests and observe RED**

Run:

```bash
pnpm --filter @aegishub/bounty-core exec vitest run test/policy.test.ts
```

Expected: FAIL because the policy functions do not exist.

- [ ] **Step 3: Implement the pure policy evaluator**

Export these functions from `policy.ts`:

```ts
export function computePolicyStatus(input: {
  snapshot: PolicySnapshot;
  retrievals: readonly PolicySourceResult[];
  now: Date;
}): PolicyStatus;

export function evaluatePolicyGate(input: PolicyGateInput): PolicyGateDecision;
export function policyFingerprint(snapshot: PolicySnapshot): string;
```

The fixed enforcement object rejects:

- non-GitHub and non-lab targets;
- third-party repositories;
- credential attacks and social engineering;
- enumeration campaigns;
- high-volume scanning, scraping, fuzzing, or brute force;
- availability and resource-exhaustion testing;
- collection of third-party PII or secrets;
- persistence without verified cleanup;
- raw sockets, arbitrary redirects, arbitrary HTTP hosts, arbitrary GraphQL, and shell execution.

The evaluator operates on typed classifications, not free-text keyword guesses. Unknown classifications fail parsing.

- [ ] **Step 4: Write source canonicalization tests**

Use local HTML fixtures embedded in the test. Prove that navigation, scripts, styles, tag attributes, and whitespace changes do not change the canonical hash, while a change to a rule inside `main` does. Prove a body without `main` fails closed instead of hashing the whole page.

The canonicalizer signature is:

```ts
export function canonicalizePolicyHtml(html: string): string;
export function hashCanonicalPolicyHtml(html: string): string;
```

Cap each source body at `2_000_000` bytes before canonicalization.

- [ ] **Step 5: Implement the allowlisted policy source client**

Hard-code exactly:

```ts
export const POLICY_SOURCE_URLS = [
  'https://bounty.github.com/rules.html',
  'https://bounty.github.com/scope.html',
  'https://bounty.github.com/targets.html',
  'https://bounty.github.com/ineligible.html',
  'https://bounty.github.com/rewards.html'
] as const;
```

Use `redirect: 'manual'`, a `20_000 ms` timeout, no cookies, no authorization headers, and no retry on a redirect. A transport failure becomes a typed unavailable result; malformed content becomes `review-required`, not `fresh-unverified`.

Canonicalization must:

1. select one `main` element by explicit opening/closing markers;
2. remove `script`, `style`, `nav`, and `footer` blocks;
3. replace block-closing tags with line breaks;
4. strip remaining tags;
5. normalize common HTML entities and Unicode NFC;
6. collapse horizontal whitespace and repeated blank lines;
7. reject empty normalized content.

- [ ] **Step 6: Add the review-only snapshot generator**

`review-policy.ts` fetches the five fixed URLs, prints a human-readable content summary and old/new hashes, and exits without writing unless `--write --reviewed-at 2026-08-13T00:00:00.000Z` is present. It may update retrieval timestamps and source hashes only; it must import the fixed enforcement object from code and cannot derive or relax enforcement from web content.

Run:

```bash
pnpm --filter @aegishub/bounty-runtime exec tsx scripts/review-policy.ts
pnpm --filter @aegishub/bounty-runtime exec tsx scripts/review-policy.ts -- --write --reviewed-at 2026-08-13T00:00:00.000Z
```

Expected: the first command previews without writing; after manually comparing the normalized sections with the approved source pages, the second writes a schema-valid snapshot with policy version `github-bounty-2026-08-13.1` and five real SHA-256 values. Never insert placeholder hashes.

- [ ] **Step 7: Add runtime snapshot loading and local change detection**

`loadReviewedPolicySnapshot` validates the checked-in JSON and returns its stable fingerprint. `PolicyMonitor` stores the fingerprint used to plan a run and re-reads the local snapshot before each network operation. A changed local snapshot stops the run with `policy_changed_during_run`. Remote source freshness is checked once immediately before execution; do not make five policy-page requests before every GitHub operation.

- [ ] **Step 8: Run focused and package checks**

```bash
pnpm --filter @aegishub/bounty-core exec vitest run test/policy.test.ts
pnpm --filter @aegishub/bounty-runtime exec vitest run test/policy-source.test.ts
pnpm --filter @aegishub/bounty-core lint
pnpm --filter @aegishub/bounty-core typecheck
pnpm --filter @aegishub/bounty-runtime lint
pnpm --filter @aegishub/bounty-runtime typecheck
```

Expected: all exit `0` and tests use no live network.

- [ ] **Step 9: Commit the reviewed policy gate**

```bash
git add packages/bounty-core/src/policy.ts packages/bounty-core/src/index.ts packages/bounty-core/test/policy.test.ts packages/bounty-runtime/src/policy packages/bounty-runtime/policy packages/bounty-runtime/scripts/review-policy.ts packages/bounty-runtime/test/policy-source.test.ts
git commit -m "feat(bounty): enforce reviewed GitHub bounty policy"
```

## Task 3: Build Budgets, Redaction, Differential Classification, and Approval Fingerprints

**Files:**

- Create: `packages/bounty-core/src/budget.ts`
- Create: `packages/bounty-core/src/redaction.ts`
- Create: `packages/bounty-core/src/differential.ts`
- Create: `packages/bounty-core/src/approval.ts`
- Create: `packages/bounty-core/src/analysis-pack.ts`
- Modify: `packages/bounty-core/src/index.ts`
- Create: `packages/bounty-core/test/budget.test.ts`
- Create: `packages/bounty-core/test/redaction.property.test.ts`
- Create: `packages/bounty-core/test/differential.test.ts`
- Create: `packages/bounty-core/test/approval.test.ts`
- Create: `packages/bounty-core/test/analysis-pack.test.ts`

- [ ] **Step 1: Write failing budget and property tests**

Assert:

- Every experiment ceiling is less than or equal to the Phase 1 ceiling.
- Request and mutation reservations are atomic.
- Counters never underflow or exceed their maximum under arbitrary sequences.
- A rejected reservation leaves counters unchanged.
- `maxMutationRetries` must equal `0`.

Use fast-check locally:

```ts
fc.assert(
  fc.property(fc.array(fc.constantFrom('read', 'mutation')), (actions) => {
    const counter = new BudgetCounter({
      maxRequests: 100,
      maxMutations: 10
    });

    for (const action of actions) {
      counter.tryReserve(action);
      expect(counter.snapshot().requests).toBeLessThanOrEqual(100);
      expect(counter.snapshot().mutations).toBeLessThanOrEqual(10);
    }
  })
);
```

- [ ] **Step 2: Implement ceiling validation and reservation**

Export:

```ts
export const PHASE_ONE_BUDGET_CEILINGS: Readonly<BudgetSettings>;
export function validateRequestedBudgets(requested: BudgetSettings): BudgetSettings;

export class BudgetCounter {
  constructor(settings: Pick<BudgetSettings, 'maxRequests' | 'maxMutations'>);
  tryReserve(kind: 'read' | 'mutation'): BudgetReservation;
  snapshot(): Readonly<{ requests: number; mutations: number }>;
}
```

`BudgetReservation` is either `{ ok: true; ordinal: number }` or `{ ok: false; reason: 'request_budget_exhausted' | 'mutation_budget_exhausted' }`. Do not expose decrement methods.

- [ ] **Step 3: Write failing redaction tests**

Seed arbitrary nested objects and text with:

- `Authorization` and `Cookie` headers;
- `ghp_`, `github_pat_`, `ghu_`, `ghs_`, `ghr_`, `ghe_`, and `r1.` token forms;
- JWT-shaped strings;
- device codes and user codes;
- password/secret/key/token field names;
- signed URL query fields;
- emails and unexpected personal identifiers;
- high-entropy values.

Assert the secret never appears in output, thrown errors, or JSON serialization. Assert equal values in one run produce equal placeholders, while separate run keys produce different placeholders. Add a property test that injects each generated secret into random JSON paths.

- [ ] **Step 4: Implement a run-local HMAC redactor and final scanner**

Use a random 32-byte run key and placeholders:

```ts
export class RunRedactor {
  static create(): RunRedactor;
  redactJson(value: JsonValue, policy?: RedactionAllowlist): JsonValue;
  redactText(value: string, kindHint?: RedactionKind): string;
  assertNoSuspectedSecret(value: string, allowlist?: readonly RegExp[]): void;
  destroy(): void;
}
```

Placeholder format is `[REDACTED:<kind>:<12 lowercase hex>]`, where the suffix is the first 12 hex characters of HMAC-SHA-256. `destroy()` overwrites the in-memory key buffer and makes later calls throw `redactor_destroyed`.

Allowlist only schema-owned hashes, UUIDs, GitHub node IDs, synthetic fixture constants, and fields explicitly retained by an operation normalizer. Never allowlist an entire body.

- [ ] **Step 5: Write differential-state tests**

Build fixtures for:

1. owner `200` + two researcher `404` + two anonymous `404` + matching owner repeat → `expected`;
2. researcher receives protected marker content twice, owner independently verifies no intended grant → `anomalous` with candidate;
3. one transient researcher `500` → `inconclusive`;
4. policy rejection → `policy_blocked`;
5. cleanup not verified → `dirty`;
6. response difference containing only request ID, timestamp, rate counter, signed query, ordering, or actor self-link → no anomaly.

The classifier signature is:

```ts
export function classifyRun(input: DifferentialInput): DifferentialResult;
```

A candidate is emitted only when all of these typed predicates are true: a named boundary was crossed, at least two consistent untrusted observations exist, protected data or an independently verified side effect exists, no ineligible class matches, impact is confidentiality or integrity on lab-owned data, and cleanup is clean or not applicable.

- [ ] **Step 6: Implement deterministic normalization and classification**

Normalize with versioned profiles selected by catalog ID. Never accept a normalization callback from YAML. Persist:

- normalized status/error class;
- an allowlisted normalized JSON body;
- raw-body SHA-256;
- protected-data and out-of-lab booleans;
- verified side-effect state;
- repeat group.

Return exactly one `RunResultState`. When evidence is incomplete, prefer `inconclusive` over `anomalous`.

- [ ] **Step 7: Write and implement approval-fingerprint tests**

The fingerprint input is exactly:

```ts
export interface ApprovalFingerprintInput {
  plan: ExperimentPlan;
  ownerId: number;
  researcherId: number;
  manifestSha256: string;
  policyFingerprint: string;
  catalogFingerprint: string;
}
```

`createApprovalFingerprint` is SHA-256 of stable JSON. Changing any operation, parameter, actor, cleanup step, budget, identity, manifest, policy, or catalog changes it. `ApprovalGrant` contains the full fingerprint, a random nonce, and an expiry no more than five minutes in the future; it exists only in memory and can be consumed once.

- [ ] **Step 8: Constrain the future analyst boundary**

`buildAnalysisPack` accepts only sanitized observations, evidence IDs, selected sanitized prior summaries, policy excerpt IDs, and available operation IDs. `analystOutputSchema` allows hypotheses, benign explanations, evidence gaps, suggested existing operation IDs, actor arrangements, and a cited rationale. Tests reject URL, method, headers, GraphQL, code, script, command, approval, token, and raw-body fields.

- [ ] **Step 9: Run all pure-package tests**

```bash
pnpm --filter @aegishub/bounty-core test
pnpm --filter @aegishub/bounty-core lint
pnpm --filter @aegishub/bounty-core typecheck
pnpm --filter @aegishub/bounty-core build
```

Expected: all exit `0` and property tests report their configured number of local runs.

- [ ] **Step 10: Commit deterministic safety logic**

```bash
git add packages/bounty-core
git commit -m "feat(bounty): add deterministic safety and diff engines"
```

## Task 4: Implement Session Vaults, Optional Keyring, and Device Flow Identity Separation

**Files:**

- Create: `packages/bounty-runtime/src/auth/vault.ts`
- Create: `packages/bounty-runtime/src/auth/device-flow.ts`
- Create: `packages/bounty-runtime/src/auth/identity-manager.ts`
- Modify: `packages/bounty-runtime/src/index.ts`
- Create: `packages/bounty-runtime/test/vault.test.ts`
- Create: `packages/bounty-runtime/test/device-flow.test.ts`
- Create: `packages/bounty-runtime/test/identity-manager.test.ts`

- [ ] **Step 1: Write failing vault tests**

Test `MemoryCredentialVault` and an injected fake keyring implementation. Assert:

- records are isolated by `owner` and `researcher`;
- `clear` deletes both;
- malformed keyring JSON is deleted and rejected;
- keyring load/set/delete failures become a capability error without plaintext fallback;
- `anonymous` cannot be passed to a vault method;
- no record is returned after its access-token expiry;
- serialized errors and captured console output do not contain token or refresh-token fixture strings.

Use a runtime-internal strict record:

```ts
interface CredentialRecord {
  schemaVersion: 1;
  actor: AuthenticatedActor;
  accessToken: string;
  refreshToken?: string;
  expiresAt?: string;
  refreshTokenExpiresAt?: string;
  identity: GitHubIdentity;
  createdAt: string;
}
```

- [ ] **Step 2: Implement memory and optional keyring vaults**

`MemoryCredentialVault` stores records in a private `Map` and clears replaced string references. `KeyringCredentialVault` dynamically imports `@napi-rs/keyring` and uses service `AegisHub Bounty Mode` with account names `github-owner-v1` and `github-researcher-v1`.

The keyring adapter must be injectable:

```ts
export interface KeyringEntry {
  setPassword(value: string): void;
  getPassword(): string | null;
  deletePassword(): void;
}

export type KeyringEntryFactory = (service: string, account: string) => KeyringEntry;
```

If import or a probe set/get/delete fails, return `keychain_unavailable` and keep session-only behavior. Never write credentials to `.aegishub`, `.env`, process arguments, standard output, or logs.

Capability probing uses an account name formed from `capability-probe-` plus a random UUID under the same service and deletes it in `finally`. It never reads, overwrites, or deletes an owner/researcher record.

- [ ] **Step 3: Write Device Flow protocol tests**

With an injected Octokit strategy factory, assert:

- `clientType` is `github-app`;
- only the configured client ID is supplied;
- no scope or client secret is sent;
- verification URL and user code reach only the ephemeral callback;
- device code never reaches a logger or evidence object;
- access, refresh, and expiry fields are mapped into the internal record;
- denied, expired, and slow-down responses become redacted typed errors.
- a non-interactive terminal is rejected before requesting a device code.

- [ ] **Step 4: Implement the strict Device Flow client**

Export:

```ts
export interface DeviceVerification {
  verificationUri: 'https://github.com/login/device';
  userCode: string;
  expiresInSeconds: number;
  intervalSeconds: number;
}

export interface DeviceFlowClient {
  authenticate(
    actor: AuthenticatedActor,
    onVerification: (verification: DeviceVerification) => Promise<void> | void
  ): Promise<UnverifiedCredential>;
}
```

Wrap `createOAuthDeviceAuth`. When providing a custom Octokit request for tests, its fetch adapter may logically address only the two Device Flow URLs. Production fetch uses `redirect: 'manual'` and rejects every redirect. Do not expose the Octokit auth hook to the experiment transport.

- [ ] **Step 5: Write identity-manager tests**

Inject an `AuthenticatedUserGateway` that returns synthetic `GET /user` results. Assert:

- identity is fetched immediately after Device Flow;
- a login name change with the same immutable ID is accepted and updated;
- owner ID equal to researcher ID is rejected before vault persistence;
- failed identity lookup discards the unverified credential;
- expired persisted credentials are deleted and trigger on-demand Device Flow;
- logout deletes one record; revoke-local clears both and returns the GitHub settings URL without opening a browser.

- [ ] **Step 6: Implement verified identity lifecycle**

Export:

```ts
export class IdentityManager implements TokenProvider {
  login(input: LoginInput): Promise<GitHubIdentity>;
  requireIdentity(actor: AuthenticatedActor, input: RequireIdentityInput): Promise<GitHubIdentity>;
  getUsableToken(actor: AuthenticatedActor): Promise<string>;
  status(): Promise<IdentityStatus[]>;
  logout(actor: AuthenticatedActor): Promise<void>;
  revokeLocal(): Promise<{ settingsUrl: 'https://github.com/settings/applications' }>;
}
```

Keep unverified tokens in a local variable only. Verify `GET /user`, enforce distinct IDs against the other stored actor, then persist if `--persist` was explicitly requested. For session-only commands that need credentials, `requireIdentity` initiates Device Flow in that same process.

When `expiresAt` is reached, delete the record and require a fresh Device Flow. Retain a returned refresh token only inside the selected vault so it can be safely removed on logout; do not attempt refresh in Phase 1.

- [ ] **Step 7: Run focused auth checks**

```bash
pnpm --filter @aegishub/bounty-runtime exec vitest run test/vault.test.ts test/device-flow.test.ts test/identity-manager.test.ts
pnpm --filter @aegishub/bounty-runtime lint
pnpm --filter @aegishub/bounty-runtime typecheck
```

Expected: all exit `0`. Search captured test output for every seeded token and assert zero matches.

- [ ] **Step 8: Commit authentication foundations**

```bash
git add packages/bounty-runtime/src/auth packages/bounty-runtime/src/index.ts packages/bounty-runtime/test/vault.test.ts packages/bounty-runtime/test/device-flow.test.ts packages/bounty-runtime/test/identity-manager.test.ts
git commit -m "feat(bounty): add separated Device Flow identities"
```

## Task 5: Add the Immutable Lab Manifest, Marker, and Proof-of-Control Workflow

**Files:**

- Create: `packages/bounty-runtime/src/lab/store.ts`
- Create: `packages/bounty-runtime/src/lab/verifier.ts`
- Modify: `packages/bounty-runtime/src/index.ts`
- Create: `packages/bounty-runtime/test/lab-store.test.ts`
- Create: `packages/bounty-runtime/test/lab-verifier.test.ts`

- [ ] **Step 1: Write failing lab-store tests**

Use a per-test temporary directory. Assert:

- manifest path is exactly `.aegishub/bounty-lab.json` beneath the supplied workspace root;
- writes use a sibling temporary file and atomic rename;
- the state directory and files are mode `0700`/`0600` where the platform supports POSIX modes;
- an existing symlink at `.aegishub`, the manifest, or any state file is rejected;
- malformed or unknown manifest fields fail closed;
- a repository rename is accepted only when immutable repository ID and node ID still match;
- a name resolving to a different ID is rejected;
- returned manifest hashes are stable SHA-256 of canonical JSON.

- [ ] **Step 2: Implement the local lab store**

Export:

```ts
export class LabStore {
  constructor(workspaceRoot: string);
  load(): Promise<{ manifest: LabManifest; sha256: string }>;
  writeNew(manifest: LabManifest): Promise<{ sha256: string }>;
  replaceVerified(
    expectedSha256: string,
    manifest: LabManifest
  ): Promise<{ sha256: string }>;
  statePath(...segments: readonly string[]): string;
}
```

`statePath` accepts fixed internal segments only; it is not exposed to experiment documents. Reject `..`, absolute paths, null bytes, and symlinks. `writeNew` refuses to overwrite. `replaceVerified` performs compare-and-swap against the current manifest hash.

- [ ] **Step 3: Write failing marker and proof tests**

Inject a `LabEnrollmentGateway` with typed methods, not raw HTTP:

```ts
export interface LabEnrollmentGateway {
  resolveOwnedRepository(fullName: string, ownerToken: string): Promise<ResolvedRepository>;
  readMarker(repository: ResolvedRepository, ownerToken: string): Promise<RemoteMarker | 'missing'>;
  createMarker(input: CreateMarkerInput, ownerToken: string): Promise<RemoteMarker>;
  deleteMarker(input: DeleteMarkerInput, ownerToken: string): Promise<void>;
}
```

Assert:

- owner and researcher immutable IDs must already be distinct;
- repository `owner.id` must equal the authenticated owner ID;
- repository must be private for the Phase 1 bundled experiment;
- an organization-owned repository returns `organization_owner_verification_unavailable` under Phase 1 permissions;
- an existing different marker is never overwritten;
- marker lab UUID, repository ID, owner ID, schema version, and nonce must all match;
- local manifest is written only after a read-back verifies the marker;
- a failure after remote creation requests the declared rollback;
- rollback failure writes a dirty-state record and returns `dirty`.

- [ ] **Step 4: Implement marker creation and verification**

Generate:

- lab ID with `randomUUID()`;
- a 32-byte base64url control nonce;
- marker JSON using stable serialization;
- marker hash with SHA-256.

The marker is:

```json
{
  "schemaVersion": 1,
  "labId": "95f38cca-42e2-4b7d-82e6-f13f4549b2f3",
  "repositoryId": 3003,
  "owner": { "kind": "user", "id": 1001 },
  "controlNonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}
```

`LabVerifier.verify` always resolves current repository metadata first, checks immutable IDs, then reads and validates the marker. It may update display login/full-name fields only through `replaceVerified` after every immutable check passes.

Define a write-ahead port now so enrollment uses the same journal implemented in Task 8:

```ts
export interface ConfigurationMutationJournal {
  prepare(entry: ConfigurationMutationEntry): Promise<void>;
  markSent(entryId: string): Promise<void>;
  markVerified(entryId: string): Promise<void>;
  markRolledBack(entryId: string): Promise<void>;
  markDirty(entryId: string, reason: string): Promise<void>;
}
```

The marker is a deliberate retained configuration change. Its inverse delete operation is journaled for rollback on partial failure, but successful initialization ends `verified-retained` rather than deleting the valid marker.

- [ ] **Step 5: Verify lab status behavior**

`lab status` data must distinguish:

- `missing`;
- `unverified`;
- `verified`;
- `renamed-and-reverified`;
- `dirty`;
- `blocked` with a stable reason.

No status object may contain marker nonce, token, or raw marker content. Display only the marker SHA-256.

- [ ] **Step 6: Run lab tests and checks**

```bash
pnpm --filter @aegishub/bounty-runtime exec vitest run test/lab-store.test.ts test/lab-verifier.test.ts
pnpm --filter @aegishub/bounty-runtime lint
pnpm --filter @aegishub/bounty-runtime typecheck
```

Expected: all exit `0` on Linux. Path and symlink tests branch only where Windows semantics differ; they may not be blanket-skipped.

- [ ] **Step 7: Commit the lab boundary**

```bash
git add packages/bounty-runtime/src/lab packages/bounty-runtime/src/index.ts packages/bounty-runtime/test/lab-store.test.ts packages/bounty-runtime/test/lab-verifier.test.ts
git commit -m "feat(bounty): verify immutable owned-resource labs"
```

## Task 6: Implement the Typed Operation Catalog and Guarded GitHub Transport

**Files:**

- Create: `packages/bounty-core/src/catalog.ts`
- Modify: `packages/bounty-core/src/index.ts`
- Create: `packages/bounty-core/test/catalog.property.test.ts`
- Create: `packages/bounty-runtime/src/transport/operation-catalog.ts`
- Create: `packages/bounty-runtime/src/transport/rate-limiter.ts`
- Create: `packages/bounty-runtime/src/transport/guarded-transport.ts`
- Modify: `packages/bounty-runtime/src/index.ts`
- Create: `packages/bounty-runtime/test/operation-catalog.test.ts`
- Create: `packages/bounty-runtime/test/guarded-transport.test.ts`
- Create: `packages/bounty-runtime/test/rate-limiter.test.ts`

- [ ] **Step 1: Write catalog escape and fingerprint property tests**

For arbitrary Unicode strings, slashes, dot segments, percent encodings, query delimiters, fragments, and host-looking values, prove:

- rendered REST URL origin remains `https://api.github.com`;
- path parameters occupy only their encoded segment;
- no parameter can introduce a query or fragment;
- experiment-visible operations cannot use identity, enrollment, or cleanup-only entries;
- GraphQL requests select a checked-in document ID, never query text;
- changing any descriptor field changes the catalog fingerprint.

The pure catalog shape is:

```ts
export interface OperationDescriptor {
  id: OperationId;
  version: 1;
  protocol: 'rest' | 'graphql';
  purpose: readonly ('identity' | 'enrollment' | 'experiment' | 'cleanup')[];
  classification: 'read' | 'mutation';
  allowedActors: readonly Actor[];
  permission: 'metadata:read' | 'contents:read' | 'contents:write';
  retry: 'safe-read' | 'never';
  cleanupOperationId?: OperationId;
  normalizationProfile: string;
  retainedResponseHeaders: readonly (
    | 'content-type'
    | 'etag'
    | 'x-github-media-type'
  )[];
  retainedFields: readonly string[];
}
```

- [ ] **Step 2: Implement and freeze the Phase 1 catalog**

Catalog version is `1.0.0`. Include only:

| ID | Wire operation | Purpose | Actors | Class |
|---|---|---|---|---|
| `github.rest.users.get-authenticated.v1` | `GET /user` | identity | owner, researcher | read |
| `github.graphql.viewer-identity.v1` | named `ViewerIdentityV1` at `POST /graphql` | identity | owner, researcher | read |
| `github.rest.repos.get.v1` | `GET /repos/{owner}/{repo}` | enrollment, experiment | all | read |
| `github.rest.contents.get-lab-marker.v1` | `GET /repos/{owner}/{repo}/contents/.aegishub-lab.json` | enrollment, experiment, cleanup | all | read |
| `github.rest.contents.put-lab-marker.v1` | `PUT /repos/{owner}/{repo}/contents/.aegishub-lab.json` | enrollment | owner | mutation |
| `github.rest.contents.delete-lab-marker.v1` | `DELETE /repos/{owner}/{repo}/contents/.aegishub-lab.json` | cleanup | owner | mutation |

`ViewerIdentityV1` is a constant in code:

```graphql
query ViewerIdentityV1 {
  viewer {
    databaseId
    id
    login
  }
}
```

Each operation has a strict parameter schema. Repository operations receive `owner` and `repo` separately plus expected repository ID/node ID in execution context. Marker write parameters accept only base64 of a schema-valid marker, exact default branch, commit message fixed by runtime, and optional current blob SHA.

Normalization allowlists are equally fixed:

- authenticated-user/viewer: immutable ID, node ID, login;
- repository: ID, node ID, full name, owner ID/login, `private`, visibility, default branch, and boolean permission flags needed to distinguish legitimate researcher access;
- marker read: content blob SHA plus validated marker schema/lab/repository/owner IDs; the control nonce is compared to the manifest and then retained only as its SHA-256;
- denied response: status and documented error class only;
- marker mutation: content blob SHA and commit SHA only.

- [ ] **Step 3: Write failing rate-limiter tests with a fake clock**

Assert:

- at most one operation is in flight;
- two initial tokens may be consumed as the allowed burst;
- the third waits until one second of replenishment;
- abort interrupts waiting immediately;
- no queued operation executes after emergency stop;
- rate state is per run, not process-global.

- [ ] **Step 4: Implement a deterministic token bucket and semaphore**

Inject:

```ts
export interface RuntimeClock {
  nowMs(): number;
  sleep(ms: number, signal: AbortSignal): Promise<void>;
}

export interface RuntimeRandom {
  jitter(maxExclusive: number): number;
}
```

Production uses monotonic time and cryptographic jitter. Tests use exact values. Keep the semaphore capacity equal to the validated `concurrency`, whose Phase 1 maximum is one.

- [ ] **Step 5: Write guarded-transport failure tests**

With an injected logical HTTP executor, test:

- owner/researcher get exactly one `Authorization: Bearer <token>` header at the last possible moment;
- anonymous gets no authentication, cookie, or client-identifying secret;
- retained request metadata never includes authorization;
- `X-GitHub-Api-Version` is pinned to `2022-11-28` and `Accept` to `application/vnd.github+json`;
- `User-Agent` is fixed to `aegishub-bounty/0.1` and GraphQL/mutation content type is fixed to `application/json`;
- redirect, `401`, `429`, secondary-rate-limit/abuse `403`, timeout, body over `262_144` bytes, out-of-lab ID, unexpected credential/PII, and budget exhaustion stop the run;
- an ordinary access-denied `403` or private-resource `404` becomes an observation;
- safe reads retry transport failures and transient `5xx` at most twice with bounded exponential backoff;
- mutations never retry automatically;
- a lost mutation response becomes `mutation_outcome_unknown` for independent verification;
- every error string passes the redactor.

- [ ] **Step 6: Implement guarded request execution**

Export:

```ts
export class GuardedGitHubTransport implements GitHubOperationExecutor {
  execute(request: PlannedOperation, signal: AbortSignal): Promise<Observation>;
}
```

Execution order is fixed:

1. assert policy fingerprint unchanged;
2. resolve catalog descriptor and operation-specific strict parameters;
3. assert purpose and actor;
4. assert repository full name and immutable IDs against verified manifest context;
5. reserve request/mutation budget for the physical attempt;
6. acquire rate and concurrency permit;
7. fetch actor token only when needed;
8. construct a new fixed-origin URL from encoded segments;
9. send with timeout and `redirect: 'manual'`;
10. read no more than the operation/retention byte cap;
11. classify stop conditions before retry logic;
12. hash raw bytes, parse using the operation response schema, enforce resource IDs;
13. normalize and redact allowlisted fields and only the descriptor's response-header allowlist;
14. discard raw bytes and token before returning the observation.

Every retry and independent verification is another physical request and must reserve rate and request budget. A mutation reserves the mutation counter only once, before its sole send attempt; outcome verification reserves a read request. Budget exhaustion during retry or verification stops the run.

The production HTTP executor accepts only HTTPS. The local fake-server adapter lives under `test/support` and rewrites an already validated logical GitHub URL to loopback; no base-URL override exists in production constructors.

- [ ] **Step 7: Wire identity and lab gateways through catalog operations**

Implement concrete adapters for `AuthenticatedUserGateway` and `LabEnrollmentGateway` on top of `GuardedGitHubTransport` with explicit `identity`/`enrollment` execution contexts. The experiment loader cannot select those purposes.

During first enrollment, `resolveOwnedRepository` is the only operation allowed before manifest pinning. It must verify the returned repository owner's immutable user ID before returning an enrollment scope. Every subsequent repository call uses the pinned ID.

- [ ] **Step 8: Run catalog, property, limiter, and transport tests**

```bash
pnpm --filter @aegishub/bounty-core exec vitest run test/catalog.property.test.ts
pnpm --filter @aegishub/bounty-runtime exec vitest run test/operation-catalog.test.ts test/rate-limiter.test.ts test/guarded-transport.test.ts
pnpm --filter @aegishub/bounty-core lint
pnpm --filter @aegishub/bounty-core typecheck
pnpm --filter @aegishub/bounty-runtime lint
pnpm --filter @aegishub/bounty-runtime typecheck
```

Expected: all exit `0`; no production test performs DNS or opens a non-loopback socket.

- [ ] **Step 9: Commit the reviewed network boundary**

```bash
git add packages/bounty-core/src/catalog.ts packages/bounty-core/src/index.ts packages/bounty-core/test/catalog.property.test.ts packages/bounty-runtime/src/transport packages/bounty-runtime/src/index.ts packages/bounty-runtime/test/operation-catalog.test.ts packages/bounty-runtime/test/rate-limiter.test.ts packages/bounty-runtime/test/guarded-transport.test.ts
git commit -m "feat(bounty): guard GitHub operations by catalog"
```

## Task 7: Add the Declarative Experiment Loader, Planner, and One-Run Approval

**Files:**

- Create: `packages/bounty-runtime/src/experiments/loader.ts`
- Create: `packages/bounty-runtime/src/experiments/planner.ts`
- Modify: `packages/bounty-runtime/src/index.ts`
- Create: `packages/bounty-runtime/test/experiment-loader.test.ts`
- Create: `packages/bounty-runtime/test/experiment-planner.test.ts`

- [ ] **Step 1: Write hostile YAML/JSON loader tests**

Reject:

- files larger than `65_536` bytes;
- YAML aliases, merges, duplicate keys, custom tags, multiple documents, and non-core types;
- JSON duplicate safety fields when detectable before parse;
- unknown schema fields;
- raw URL, HTTP method, header, query text, shell, code, callback, script, and dynamic expression fields;
- unknown operation IDs and cleanup IDs;
- local experiment paths outside `.aegishub/experiments`;
- symlinked experiment directories/files;
- requested budgets above any Phase 1 ceiling.

Accept the same valid experiment represented as strict YAML and JSON and produce identical stable hashes.

- [ ] **Step 2: Implement bounded declarative loading**

Use `yaml.parseDocument` with core schema, unique keys, and aliases disabled. Convert to plain JSON, validate `experimentSchema`, then validate each step's parameters against its catalog operation schema.

Built-ins resolve from `<bounty-runtime-root>/experiments`. User-local experiments resolve by stable ID from `<workspace>/.aegishub/experiments`. A duplicate local ID cannot shadow a built-in ID.

- [ ] **Step 3: Write planner invariant tests**

Assert planning fails unless:

- policy state permits the read/mutation mix;
- owner and researcher IDs are distinct;
- manifest and repository marker are currently verified;
- no dirty state exists for mutation plans;
- all capabilities and operation families are approved;
- every operation is experiment-visible and actor-compatible;
- every repository parameter resolves to the pinned full name and immutable ID;
- every mutation has the catalog-declared inverse in cleanup;
- phase order is setup → baseline → probe → verify → repeat → cleanup;
- total declared operations fit budgets;
- untrusted probes meet the declared minimum repeat count.

Planning performs no GitHub mutation and returns printable operations with endpoint templates, never expanded tokens or raw authorization.

- [ ] **Step 4: Implement immutable experiment plans**

Export:

```ts
export class ExperimentPlanner {
  plan(input: PlanExperimentInput): ExperimentPlan;
}
```

Each planned operation records:

- ordinal and phase;
- step ID;
- actor;
- catalog operation ID/version;
- normalized endpoint template;
- sanitized validated parameters;
- read/mutation classification;
- expected effect;
- required cleanup operation;
- request and mutation budget contribution.

Freeze the returned plan recursively. Compute plan hash, manifest hash, policy fingerprint, and catalog fingerprint before presenting it.

- [ ] **Step 5: Connect mutation approval**

The terminal layer will display the full plan and require the user to type `RUN <first 12 characters of fingerprint>`. The planner/runtime API receives an `ApprovalGrant` object, not a boolean. It verifies full fingerprint, nonce, expiry, and single-use state immediately before the first mutation.

For read-only plans, record `approval: { kind: 'verified-lab-read-only' }`. For mutating plans, reject `stdin.isTTY === false` and any non-interactive option before constructing a grant.

- [ ] **Step 6: Run loader/planner tests**

```bash
pnpm --filter @aegishub/bounty-runtime exec vitest run test/experiment-loader.test.ts test/experiment-planner.test.ts
pnpm --filter @aegishub/bounty-runtime lint
pnpm --filter @aegishub/bounty-runtime typecheck
```

Expected: all exit `0` and hostile fixtures result in typed validation errors, not crashes.

- [ ] **Step 7: Commit declarative planning**

```bash
git add packages/bounty-runtime/src/experiments/loader.ts packages/bounty-runtime/src/experiments/planner.ts packages/bounty-runtime/src/index.ts packages/bounty-runtime/test/experiment-loader.test.ts packages/bounty-runtime/test/experiment-planner.test.ts
git commit -m "feat(bounty): plan declarative bounded experiments"
```

## Task 8: Implement the Runner, Write-Ahead Cleanup Journal, Dirty State, and Emergency Stop

**Files:**

- Create: `packages/bounty-runtime/src/experiments/journal.ts`
- Create: `packages/bounty-runtime/src/experiments/active-run.ts`
- Create: `packages/bounty-runtime/src/experiments/runner.ts`
- Modify: `packages/bounty-runtime/src/index.ts`
- Create: `packages/bounty-runtime/test/journal.test.ts`
- Create: `packages/bounty-runtime/test/active-run.test.ts`
- Create: `packages/bounty-runtime/test/runner.test.ts`

- [ ] **Step 1: Write journal state-machine tests**

Allow only:

```text
prepared -> sent -> observed -> verified-applied
prepared -> sent -> outcome-unknown -> verified-applied
prepared -> sent -> outcome-unknown -> verified-not-applied -> clean
observed -> verification-failed -> dirty
outcome-unknown -> verification-failed -> dirty
verified-applied -> cleanup-sent -> clean
verified-applied -> cleanup-sent -> dirty
verified-applied -> verified-retained
prepared -> rolled-back
```

`verified-retained` is allowed only for the persistent lab marker configuration operation. Reject skipped, reversed, duplicated, and post-terminal transitions. Every journal append is flushed before the corresponding network action. Reopening the journal reconstructs the same state and rejects a modified or truncated chain using hash links.

- [ ] **Step 2: Implement an append-only write-ahead journal**

Each NDJSON record includes sequence, previous-record hash, timestamp, run ID, plan fingerprint, operation ordinal, mutation state, catalog ID, sanitized parameters hash, declared inverse ID, and verification evidence ID. It never contains a token, raw request, raw response, marker nonce, or protected content.

Use file mode `0600`, `open` with append/exclusive semantics, `fsync` before mutation send, and schema validation on read. Implement both `ConfigurationMutationJournal` from Task 5 and experiment mutation journaling on the same primitive.

- [ ] **Step 3: Write active-run and stop tests**

Assert:

- one process obtains `.aegishub/active-run.json` with exclusive create;
- a second process is blocked;
- `bounty stop` requests cancellation only for the current run by creating its fixed stop-request file;
- a finished run removes the active pointer and stop file;
- a dead PID with no sent mutation is recovered as interrupted/inconclusive;
- a dead PID with an unresolved mutation marks the lab dirty before lease recovery;
- any PID that appears alive or cannot be queried is treated as active and blocks automatic recovery.

- [ ] **Step 4: Implement active-run leasing and cooperative stop**

Export:

```ts
export class ActiveRunLease {
  static acquire(store: LabStore, runId: string): Promise<ActiveRunLease>;
  signal(): AbortSignal;
  pollStopRequest(): Promise<void>;
  finish(): Promise<void>;
}

export async function requestEmergencyStop(store: LabStore): Promise<StopRequestResult>;
```

Install `SIGINT` and `SIGTERM` handlers only while a run owns a lease. The handler aborts scheduling, then lets the runner perform required cleanup. Do not call `process.exit` inside the runtime.

The active pointer and stop request both carry run ID plus a random lease nonce; the runner ignores a stale stop file whose pair does not match. Automatic recovery happens only when the recorded PID is definitely absent. `EPERM`, an existing PID, or an ambiguous platform result fails closed and requires the documented manual verification path.

- [ ] **Step 5: Write runner phase and recovery tests**

Use a scripted fake executor. Cover:

- exact phase order;
- no operation starts after stop/policy/budget failure;
- read-only interruption → `inconclusive`;
- mutation plan without matching unconsumed approval never reaches transport;
- journal is durable before first mutation;
- lost mutation response triggers independent verification and never retries mutation;
- a lost response verified as not applied ends inconclusive/clean without cleanup or replay;
- cleanup runs after probe/verify failure or interrupt when a mutation was verified;
- cleanup failure → `dirty` and future mutation planning is blocked;
- a researcher preflight showing documented repository read permission stops protected probes as `precondition_not_met` rather than manufacturing an anomaly;
- final clean state → differential classification;
- an observation containing out-of-lab or unexpected sensitive data stops immediately and is not promoted as a candidate.

- [ ] **Step 6: Implement the runner**

Export:

```ts
export class ExperimentRunner {
  run(input: RunExperimentInput): Promise<CompletedRun>;
}
```

Execution algorithm:

1. acquire active-run lease;
2. revalidate policy, identities, manifest/marker, catalog fingerprint, plan fingerprint, and budgets;
3. create journal before any mutation;
4. consume approval immediately before first mutation;
5. execute phases in order through guarded transport;
6. evaluate typed actor-relationship precondition observations before any protected follow-up probe;
7. poll stop and local policy fingerprint before every operation and backoff;
8. on unknown mutation outcome, run its catalog-declared verifier before any other action;
9. run the minimum safe repeat observations;
10. execute required cleanup in reverse dependency order;
11. verify cleanup independently;
12. set dirty state when cleanup cannot be proven;
13. classify sanitized observations;
14. pass the completed in-memory run to an injected `RunEvidenceSink`;
15. release lease in `finally` only after journal/state flush.

`RunEvidenceSink` is an interface in this task; Task 9 supplies the atomic implementation.

- [ ] **Step 7: Implement dirty-state resolution rules**

`DirtyStateStore` records run ID, repository ID, unresolved mutation operation, cleanup operation, journal path, and sanitized reason. It has no “force clean” switch. Manual resolution is accepted only after `LabVerifier` and the catalog-declared verification operation prove the expected final state.

- [ ] **Step 8: Run runner and journal tests**

```bash
pnpm --filter @aegishub/bounty-runtime exec vitest run test/journal.test.ts test/active-run.test.ts test/runner.test.ts
pnpm --filter @aegishub/bounty-runtime lint
pnpm --filter @aegishub/bounty-runtime typecheck
```

Expected: all exit `0`. Include at least one test that kills a child fixture process after `sent` and verifies dirty recovery.

- [ ] **Step 9: Commit controlled execution and recovery**

```bash
git add packages/bounty-runtime/src/experiments/journal.ts packages/bounty-runtime/src/experiments/active-run.ts packages/bounty-runtime/src/experiments/runner.ts packages/bounty-runtime/src/index.ts packages/bounty-runtime/test/journal.test.ts packages/bounty-runtime/test/active-run.test.ts packages/bounty-runtime/test/runner.test.ts
git commit -m "feat(bounty): run experiments with verified cleanup"
```

## Task 9: Write Atomic Sanitized Evidence, Reports, Checksums, and Analysis Packs

**Files:**

- Create: `packages/bounty-runtime/src/evidence/writer.ts`
- Create: `packages/bounty-runtime/src/evidence/report.ts`
- Modify: `packages/bounty-runtime/src/index.ts`
- Create: `packages/bounty-runtime/test/evidence-writer.test.ts`
- Create: `packages/bounty-runtime/test/report.test.ts`

- [ ] **Step 1: Write failing evidence-writer tests**

For a complete synthetic run, require this exact canonical layout:

```text
manifest.json
policy.json
experiment.json
plan.json
observations.ndjson
diff.json
report.md
reproduce.md
checksums.txt
```

Require `candidate.json` only for `anomalous`. Assert:

- output begins in a unique sibling temporary directory;
- target `.aegishub/runs/<run-id>` must not already exist;
- every JSON/NDJSON record validates its schema;
- all files are serialized from already sanitized values and scanned again before write;
- checksums are SHA-256, sorted by relative POSIX path, and exclude `checksums.txt` itself;
- final directory rename is the only publish step;
- simulated disk/write/rename failure does not claim success;
- an ordinary write failure preserves a safe temporary directory path for recovery;
- a suspected-secret failure deletes the unsafe temporary content best-effort and leaves only a sanitized failure record;
- output paths and existing symlinks cannot escape the runs directory;
- no token fixture appears in any file, filename, exception, or returned object.

- [ ] **Step 2: Implement schema-first serialization**

Export:

```ts
export class AtomicEvidenceWriter implements RunEvidenceSink {
  write(run: CompletedRun): Promise<EvidenceWriteResult>;
  inspect(runId: string): Promise<VerifiedEvidenceBundle>;
  export(runId: string, outputDirectory: string): Promise<EvidenceExportResult>;
}
```

Before touching disk:

1. construct all JSON values through strict evidence schemas;
2. redact each value with the run's `RunRedactor`;
3. render JSON, NDJSON, and Markdown in memory;
4. call `assertNoSuspectedSecret` on every rendered file;
5. verify every internal evidence ID and observation reference;
6. compute file bytes and expected checksums.

Then write with `0600`, flush, read back, verify byte-for-byte and checksums, run the final scanner, atomically rename, destroy the redactor key, and return the final path.

`manifest.json` is a sanitized lab snapshot containing actor/repository IDs and marker hash, not token data or control nonce. `policy.json` records policy version, status, source hashes, and excerpt IDs. Raw policy HTML is not stored.

- [ ] **Step 3: Write report-template tests**

Assert `report.md` contains:

1. summary;
2. affected GitHub surface;
3. preconditions;
4. numbered reproduction;
5. observed result;
6. expected result;
7. concrete confidentiality/integrity impact;
8. evidence index;
9. cleanup confirmation.

Assert it never contains a bounty amount, CVSS score, asserted GitHub severity, “confirmed vulnerability,” automatic-submission language, raw URL with signed query, token, marker nonce, or third-party identity.

`reproduce.md` must use catalog operation names and sanitized CLI instructions; it cannot emit curl, raw HTTP, browser cookies, shell interpolation, or arbitrary request bodies.

- [ ] **Step 4: Implement deterministic reports**

`renderReport` and `renderReproduction` accept only schema-validated `VerifiedEvidenceBundle` data. For `expected` and `inconclusive` runs, title the document as an experiment result, not a vulnerability report. For `anomalous`, title it as a candidate for human validation.

The observed/expected sections cite evidence IDs such as `obs-0004`. The candidate rationale cites the exact repeat and independent-verification IDs.

- [ ] **Step 5: Add sanitized analysis-pack export**

`export` additionally writes `analysis-pack.json` in the user-selected export directory. It is generated with `buildAnalysisPack` and is not part of the canonical run checksum set. Validate it against `analystInputSchema` and final-scan it. It contains no executable request representation.

Refuse overwrite or symlink traversal at the selected output. Export by writing a sibling temporary directory and renaming, just like the canonical bundle.

- [ ] **Step 6: Run evidence and report checks**

```bash
pnpm --filter @aegishub/bounty-runtime exec vitest run test/evidence-writer.test.ts test/report.test.ts
pnpm --filter @aegishub/bounty-runtime lint
pnpm --filter @aegishub/bounty-runtime typecheck
```

Expected: all exit `0`; the test recursively scans its generated bundle and finds none of the seeded secret values.

- [ ] **Step 7: Commit evidence generation**

```bash
git add packages/bounty-runtime/src/evidence packages/bounty-runtime/src/index.ts packages/bounty-runtime/test/evidence-writer.test.ts packages/bounty-runtime/test/report.test.ts
git commit -m "feat(bounty): export sanitized evidence bundles"
```

## Task 10: Add the Known-Safe Private-Contents Boundary Experiment

**Files:**

- Create: `packages/bounty-runtime/experiments/repo.private.contents-read-boundary.v1.yaml`
- Create: `packages/bounty-runtime/test/builtin-private-boundary.test.ts`
- Modify if required by the final schema: `packages/bounty-core/src/contracts.ts`

- [ ] **Step 1: Add a failing built-in experiment contract test**

Load the built-in by ID and assert:

- ID is `repo.private.contents-read-boundary.v1` and version is `1`;
- owner, researcher, and anonymous each exercise the reviewed repository-metadata and marker-read boundaries;
- it uses only `repos.get` and `contents.get-lab-marker` read operations;
- mutation count is zero;
- request limit is `12` or lower;
- researcher and anonymous each have at least two marker attempts;
- owner has a baseline and final repeat;
- expected denied statuses are `403` or `404`;
- protected marker fields are never retained for untrusted actors;
- no cleanup is needed;
- the declared purpose says it validates the framework and is not expected to discover a vulnerability.

- [ ] **Step 2: Check in the complete strict YAML**

Use typed parameter references, not interpolation:

```yaml
schemaVersion: 1
id: repo.private.contents-read-boundary.v1
version: 1
title: Private repository contents read boundary
researchQuestion: Can an untrusted actor read the verified lab marker from a private repository?
expectedBoundary: Only the verified owner can read private lab repository metadata and marker content.
scopeTarget: github.com
ineligibleChecks:
  - no-third-party-target
  - no-user-repository-vulnerability-claim
  - no-availability-impact
requiredCapabilities:
  - repository-read-boundary
actorRelationships:
  - distinct-authenticated-users
  - researcher-has-no-repository-access
budgets:
  concurrency: 1
  requestsPerSecond: 1
  burst: 2
  maxRequests: 12
  maxMutations: 0
  timeoutMs: 20000
  maxReadRetries: 2
  maxMutationRetries: 0
steps:
  - id: owner-repository-baseline
    phase: baseline
    actor: owner
    operationId: github.rest.repos.get.v1
    params:
      owner:
        ref: lab.repository.owner
      repo:
        ref: lab.repository.name
    repeatGroup: owner-repository
  - id: owner-marker-baseline
    phase: baseline
    actor: owner
    operationId: github.rest.contents.get-lab-marker.v1
    params:
      owner:
        ref: lab.repository.owner
      repo:
        ref: lab.repository.name
    repeatGroup: owner-marker
  - id: researcher-repository-probe
    phase: probe
    actor: researcher
    operationId: github.rest.repos.get.v1
    params:
      owner:
        ref: lab.repository.owner
      repo:
        ref: lab.repository.name
    repeatGroup: researcher-repository
  - id: researcher-marker-probe-1
    phase: probe
    actor: researcher
    operationId: github.rest.contents.get-lab-marker.v1
    params:
      owner:
        ref: lab.repository.owner
      repo:
        ref: lab.repository.name
    repeatGroup: researcher-marker
  - id: researcher-marker-probe-2
    phase: repeat
    actor: researcher
    operationId: github.rest.contents.get-lab-marker.v1
    params:
      owner:
        ref: lab.repository.owner
      repo:
        ref: lab.repository.name
    repeatGroup: researcher-marker
  - id: anonymous-repository-probe
    phase: probe
    actor: anonymous
    operationId: github.rest.repos.get.v1
    params:
      owner:
        ref: lab.repository.owner
      repo:
        ref: lab.repository.name
    repeatGroup: anonymous-repository
  - id: anonymous-marker-probe-1
    phase: probe
    actor: anonymous
    operationId: github.rest.contents.get-lab-marker.v1
    params:
      owner:
        ref: lab.repository.owner
      repo:
        ref: lab.repository.name
    repeatGroup: anonymous-marker
  - id: anonymous-marker-probe-2
    phase: repeat
    actor: anonymous
    operationId: github.rest.contents.get-lab-marker.v1
    params:
      owner:
        ref: lab.repository.owner
      repo:
        ref: lab.repository.name
    repeatGroup: anonymous-marker
  - id: owner-repository-repeat
    phase: repeat
    actor: owner
    operationId: github.rest.repos.get.v1
    params:
      owner:
        ref: lab.repository.owner
      repo:
        ref: lab.repository.name
    repeatGroup: owner-repository
  - id: owner-marker-repeat
    phase: repeat
    actor: owner
    operationId: github.rest.contents.get-lab-marker.v1
    params:
      owner:
        ref: lab.repository.owner
      repo:
        ref: lab.repository.name
    repeatGroup: owner-marker
expectation:
  kind: access-boundary
  ownerSuccessStatuses:
    - 200
  untrustedDeniedStatuses:
    - 403
    - 404
  protectedFields:
    - marker.schemaVersion
    - marker.labId
    - marker.repositoryId
    - marker.owner.id
  requireOwnerRepeat: true
  minimumConsistentUntrustedAttempts: 2
normalizationProfile: github-private-marker-v1
expectedSafeOutcome: Owner reads succeed and untrusted reads disclose no protected marker field.
anomalyCondition: The same untrusted actor receives protected marker data in at least two consistent attempts.
purpose: Framework validation against a known-safe private repository boundary; not expected to discover a vulnerability.
```

If `repeat` must occur after all `probe` steps, preserve document order by letting the planner schedule phase buckets; do not weaken phase ordering to match YAML position.

- [ ] **Step 3: Implement typed parameter-reference resolution**

If not already completed in Task 7, define the only Phase 1 references as:

```ts
export const parameterReferenceSchema = z
  .object({
    ref: z.enum([
      'lab.repository.owner',
      'lab.repository.name',
      'lab.repository.defaultBranch',
      'lab.repository.id',
      'lab.repository.nodeId'
    ])
  })
  .strict();
```

Resolve them from the currently verified repository after manifest/marker validation. A literal object with a `ref` key that is not in the enum is rejected; no environment, filesystem, prior response, or string-template reference is supported.

- [ ] **Step 4: Test known-safe and synthetic-bypass outcomes**

With scripted observations:

- GitHub-like owner `200` and untrusted `404` responses classify `expected` and omit `candidate.json`.
- A researcher metadata `200` with documented `permissions.pull: true` means the “no repository access” precondition is false: stop that actor before marker reads and classify `inconclusive` with `precondition_not_met`, never anomalous.
- Two researcher `200` marker disclosures classify `anomalous` only when marker IDs match the lab, the body is protected, owner verifies the repository remained private, repeats agree, and cleanup is not applicable.
- One disclosure plus one denial is `inconclusive`.
- A `200` response containing an out-of-lab repository ID stops instead of becoming a candidate.

- [ ] **Step 5: Run the built-in tests**

```bash
pnpm --filter @aegishub/bounty-runtime exec vitest run test/builtin-private-boundary.test.ts
pnpm --filter @aegishub/bounty-runtime typecheck
```

Expected: all exit `0`. Assert that identical parsed documents have the same fingerprint and that any semantic experiment change alters the fingerprint and invalidates prior approval. Do not pin one literal hash merely to detect an intentional source edit.

- [ ] **Step 6: Commit the first experiment**

```bash
git add packages/bounty-runtime/experiments/repo.private.contents-read-boundary.v1.yaml packages/bounty-runtime/test/builtin-private-boundary.test.ts packages/bounty-core/src/contracts.ts
git commit -m "feat(bounty): add private contents boundary experiment"
```

## Task 11: Register the Complete Bounty CLI Without Regressing Existing Commands

**Files:**

- Modify: `packages/cli/package.json`
- Modify: `packages/cli/src/index.ts`
- Create: `packages/cli/src/bounty/register-bounty-command.ts`
- Create: `packages/cli/src/bounty/services.ts`
- Create: `packages/cli/src/bounty/terminal.ts`
- Create: `packages/cli/test/bounty-command.test.ts`
- Create: `packages/cli/test/existing-command-regression.test.ts`
- Modify: `pnpm-lock.yaml`

- [ ] **Step 1: Write command-tree tests using injected services**

Register the command tree on a fresh Commander `Command` and assert exact availability:

```text
bounty policy status
bounty auth login --actor owner|researcher [--persist]
bounty auth status
bounty auth logout --actor owner|researcher
bounty auth revoke-local
bounty lab init <owner/repository>
bounty lab verify
bounty lab status
bounty experiment list
bounty experiment plan <experiment-id>
bounty experiment run <experiment-id>
bounty run inspect <run-id>
bounty evidence export <run-id> --output <directory>
bounty stop
```

Invalid actor, missing client ID, missing lab, stale policy, same identity, dirty state, non-TTY mutation, bad approval phrase, anomaly, and successful expected run each produce stable exit-code categories and a sanitized message.

- [ ] **Step 2: Implement an injectable CLI service composition root**

`services.ts` builds runtime services from:

- workspace root from `INIT_CWD` or `process.cwd()`;
- `AEGISHUB_GITHUB_APP_CLIENT_ID`;
- session vault by default;
- optional keyring only when `--persist` or persisted status is requested;
- production policy client and transport;
- terminal verification callback and approval prompter.

Tests pass `BountyCliServices` fakes directly. Runtime modules never import Commander, Chalk, Ora, or readline.

- [ ] **Step 3: Implement terminal interactions without a prompt dependency**

Use `node:readline/promises`. The terminal:

- displays the exact GitHub verification URI and short-lived user code only during Device Flow;
- never echoes access/refresh/device tokens;
- prints actor login plus immutable ID after verification;
- prints policy state and warnings;
- prints plan operations, actor, immutable target IDs, budgets, mutation count, and cleanup;
- requires `RUN <fingerprint-prefix>` for mutation;
- closes readline and clears spinner state on every path.

Do not label standard output as a credential log. Device/user codes are ephemeral UI data and must not enter report files or logger sinks.

- [ ] **Step 4: Implement every command as a thin orchestration call**

Important behavior:

- `policy status` performs only the five fixed policy reads.
- `auth login` verifies identity before optional persistence.
- commands needing a missing session credential initiate Device Flow in that same process.
- `auth status` reports persisted records and explains that session credentials are process-local.
- `auth revoke-local` deletes local records and prints `https://github.com/settings/applications` for explicit GitHub-side revocation.
- `lab init` displays and approves the marker configuration mutation, journals it, creates/reads back the marker, then writes the manifest.
- `lab verify` performs current identity/repository/marker verification.
- `lab verify` also recovers a stale active-run pointer only when the recorded PID is definitely absent and the journal proves clean; otherwise it leaves the block in place.
- `experiment plan` performs no experiment operation and prints the stable fingerprint.
- `experiment run` replans and refuses if the fingerprint changed.
- `run inspect` verifies schemas/checksums before display.
- `evidence export` refuses overwrite and reports the final sanitized path.
- `stop` only requests cooperative cancellation for the active run.

- [ ] **Step 5: Register Bounty Mode with a two-line legacy change**

In `packages/cli/src/index.ts` add the import and registration near the existing `program` setup:

```ts
import { registerBountyCommands } from './bounty/register-bounty-command.js';

registerBountyCommands(program);
```

Do not move or rewrite existing scan/report/auth logic in this task.

- [ ] **Step 6: Add CLI regression tests**

Build and use Execa to assert:

- `aegishub --help` still lists `scan`, `report`, `auth`, and `bounty`;
- top-level `aegishub auth` still prints the existing `GITHUB_TOKEN` guidance;
- `aegishub report` still parses a synthetic existing scan report;
- a small local repository scan still invokes the Rust engine and writes a valid report;
- `aegishub bounty --help` performs no network request;
- seeded token strings never appear in stdout/stderr on a fake failed login/run.

- [ ] **Step 7: Run CLI and dependency checks**

```bash
pnpm install
pnpm --filter aegishub exec vitest run test/bounty-command.test.ts test/existing-command-regression.test.ts
pnpm --filter aegishub lint
pnpm --filter aegishub typecheck
pnpm --filter aegishub build
```

Expected: all exit `0` and the lockfile changes only for the two workspace dependencies.

- [ ] **Step 8: Commit CLI integration**

```bash
git add packages/cli/package.json packages/cli/src/index.ts packages/cli/src/bounty packages/cli/test pnpm-lock.yaml
git commit -m "feat(cli): expose guarded bounty workflows"
```

## Task 12: Complete the Loopback Integration Harness and Opt-In Live Validation

**Files:**

- Create: `packages/bounty-runtime/test/support/fake-github-server.ts`
- Create: `packages/bounty-runtime/test/integration/bounty-runtime.integration.test.ts`
- Create: `packages/bounty-runtime/test/integration/faults.integration.test.ts`
- Create: `packages/bounty-runtime/test/live/private-boundary.live.test.ts`
- Modify: `packages/bounty-runtime/package.json`

- [ ] **Step 1: Implement a stateful loopback-only fake GitHub server**

Bind to `127.0.0.1` on an ephemeral port. Refuse non-loopback bind addresses. Model:

- Device Flow code creation, pending, slow-down, denial, expiry, and success;
- owner identity ID `1001` and researcher identity ID `2002`;
- private lab repository ID `3003` and node ID `R_lab`;
- marker GET/PUT/DELETE with content SHA;
- owner `200`, researcher/anonymous `404` safe behavior;
- a toggled synthetic authorization bypass;
- rename with stable ID and name reuse with changed ID;
- regular `403`, secondary-limit `403`, `401`, `429`, redirect, `500`, timeout, oversized body, secret/PII body, and out-of-lab ID;
- mutation applied with connection dropped before response;
- cleanup success and failure.

Record received logical operation ID, method, path, actor fixture, and body hash. Never record authorization header values.

- [ ] **Step 2: Exercise the actual runtime end to end**

The safe integration test runs:

1. two Device Flow logins;
2. identity separation;
3. lab enrollment and marker read-back;
4. policy current fixture;
5. built-in load and planning;
6. low-volume execution;
7. `expected` classification;
8. evidence write, checksum verification, inspect, and export.

Assert the fake server receives exactly the planned operation count, max concurrency one, and no unexpected route.

The bypass test returns protected lab marker data to researcher twice. Assert `anomalous`, concrete confidentiality impact on lab-owned data, cited repeat IDs, clean/not-applicable cleanup, candidate presence, and no assertion of severity.

- [ ] **Step 3: Add the fault-injection integration matrix**

One focused test per fault proves the approved result:

| Fault | Required result |
|---|---|
| same account | configuration rejected |
| marker mismatch | all active operations blocked |
| repository ID mismatch | immediate stop |
| stale/changed policy | active run blocked |
| `401`, `429`, secondary limit | immediate stop, no aggressive retry |
| transient read `5xx` | at most two retries, then inconclusive |
| redirect | blocked before follow |
| oversized/secret/PII body | stop and no persisted payload |
| lost mutation response | verify state, never replay mutation |
| cleanup failure | dirty, later mutation blocked |
| interrupt | no new work, required cleanup attempted |
| evidence failure | no false success |

- [ ] **Step 4: Add the explicitly opt-in live test**

Add script:

```json
{
  "scripts": {
    "test:live": "vitest run test/live/private-boundary.live.test.ts"
  }
}
```

The live test is declared with `describe.skipIf(process.env.AEGISHUB_BOUNTY_LIVE !== '1')`. When enabled, it also requires:

- `AEGISHUB_GITHUB_APP_CLIENT_ID`;
- an existing strict local manifest;
- interactive TTY for on-demand owner/researcher Device Flows;
- current policy;
- freshly verified marker;
- private directly owner-owned repository;
- explicit typed confirmation of repository ID and experiment hash.

It calls no mutation and refuses a repository not already enrolled. The normal `pnpm test` suite sees it skipped and never prompts or contacts GitHub.

- [ ] **Step 5: Run all non-live integration tests**

```bash
pnpm --filter @aegishub/bounty-runtime exec vitest run test/integration
pnpm --filter @aegishub/bounty-runtime test
pnpm --filter @aegishub/bounty-runtime lint
pnpm --filter @aegishub/bounty-runtime typecheck
pnpm --filter @aegishub/bounty-runtime build
```

Expected: all exit `0` with `AEGISHUB_BOUNTY_LIVE` absent. The fake server reports loopback-only requests.

- [ ] **Step 6: Run live validation only with the user present**

Ask the user to create/configure the GitHub App and authorize both owned accounts only at this point. Do not request passwords, cookies, 2FA codes, access tokens, refresh tokens, or the reserve account credentials.

After the user confirms the verified private lab is ready:

```bash
AEGISHUB_BOUNTY_LIVE=1 pnpm --filter @aegishub/bounty-runtime test:live
```

On PowerShell:

```powershell
$env:AEGISHUB_BOUNTY_LIVE = "1"
pnpm --filter @aegishub/bounty-runtime test:live
```

Expected: Device Flow happens in the running process; owner reads succeed, researcher/anonymous are denied, owner repeat succeeds, result is `expected`, and a sanitized evidence bundle is produced. If the user is not available, record this single manual gate as pending; never substitute another target.

- [ ] **Step 7: Commit integration and live-test harness**

```bash
git add packages/bounty-runtime/test packages/bounty-runtime/package.json
git commit -m "test(bounty): cover safe and anomalous boundaries"
```

## Task 13: Document Safe Setup, Harden CI, and Update Repository Metadata

**Files:**

- Modify: `.gitignore`
- Create: `.env.example`
- Modify: `README.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/SECURITY.md`
- Create: `docs/BOUNTY_MODE.md`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Add local-state exclusions and non-secret environment examples**

Append `.aegishub/` to `.gitignore`. Keep the remote lab marker `.aegishub-lab.json` trackable.

Create:

```dotenv
AEGISHUB_GITHUB_APP_CLIENT_ID=
AEGISHUB_BOUNTY_LIVE=0
```

State that a GitHub App client ID is public application metadata, not a credential. Never add a client secret or token example field.

- [ ] **Step 2: Write the complete operator guide**

`docs/BOUNTY_MODE.md` must include:

- purpose, non-goals, ethical/authorization boundary, and “candidate ≠ vulnerability”;
- exact GitHub App configuration: Device Flow on, expiring user tokens on, webhooks off, selected private lab repo, implicit metadata read, contents read/write, no organization permissions, no extra account permissions;
- why the directly owner-owned repository is the Phase 1 supported lab;
- session-only versus `--persist` behavior;
- App client ID setup on bash, PowerShell, Windows, WSL2, Linux, and Docker;
- login, lab init/verify, plan, run, inspect, export, stop, logout, and local/GitHub-side revocation;
- default budgets and every stop condition;
- dirty-state recovery;
- exact bundle fields and redaction guarantee;
- known-safe experiment expectations;
- opt-in live test gate;
- responsible disclosure workflow and explicit statement that AegisHub never submits.

Link the approved design, this implementation plan, GitHub's official rules/scope/targets/ineligible/rewards pages, Device Flow docs, and token-security docs.

- [ ] **Step 3: Update architecture and security docs**

`docs/ARCHITECTURE.md` explains package ownership and the rule that only bounty-runtime performs GitHub/policy I/O. `docs/SECURITY.md` states:

- never paste credentials into issues, reports, AI prompts, or fixtures;
- public issues are not a disclosure channel;
- use GitHub's official bounty process for GitHub product candidates;
- use the repository's private security contact for AegisHub itself;
- active tests are owned-lab-only and low-volume.

- [ ] **Step 4: Update README without overstating capability**

Add Bounty Mode as a Phase 1 research workbench, not an autonomous bounty finder. Update Packages, Architecture, Quick Start links, and Roadmap. Keep current scanner instructions unchanged.

- [ ] **Step 5: Make CI explicitly non-live**

At the job level set:

```yaml
env:
  AEGISHUB_BOUNTY_LIVE: "0"
```

Keep the existing install, lint, typecheck, Rust test, monorepo test, and build steps. Add no GitHub token and no production-network test. The runtime integration suite must use loopback.

- [ ] **Step 6: Verify documentation commands**

Run every non-live command shown in `docs/BOUNTY_MODE.md` through `--help` or fake services. Check all internal Markdown links and paths.

```bash
pnpm --filter aegishub build
node packages/cli/dist/index.js bounty --help
node packages/cli/dist/index.js bounty policy --help
node packages/cli/dist/index.js bounty auth --help
node packages/cli/dist/index.js bounty lab --help
node packages/cli/dist/index.js bounty experiment --help
node packages/cli/dist/index.js bounty evidence --help
```

- [ ] **Step 7: Commit docs and CI**

```bash
git add .gitignore .env.example README.md docs/ARCHITECTURE.md docs/SECURITY.md docs/BOUNTY_MODE.md .github/workflows/ci.yml
git commit -m "docs(bounty): document safe lab operation"
```

## Task 14: Perform the Completion Gate and Acceptance Review

**Files:**

- Inspect: all files changed from `main...HEAD`
- Modify only for verified defects: the smallest affected files
- Create if live validation is pending: `docs/superpowers/baselines/2026-08-13-bounty-mode-live-gate.md`

- [ ] **Step 1: Scan the implementation for unfinished or forbidden constructs**

Run:

```bash
rg -n 'TODO|FIXME|TBD|not implemented|throw new Error\(.stub' packages/bounty-core packages/bounty-runtime packages/cli/src/bounty docs/BOUNTY_MODE.md
rg -n "fetch\s*\(|https?://" packages/bounty-core packages/cli/src/bounty
rg -n "child_process|exec\s*\(|spawn\s*\(|eval\s*\(|new Function" packages/bounty-core packages/bounty-runtime/src packages/cli/src/bounty
rg -n "Authorization|Cookie|refreshToken|accessToken|device_code|github_pat_|gh[pusr]_" packages/bounty-runtime/src packages/cli/src/bounty
```

Expected:

- first command has no unfinished production path;
- pure core and CLI contain no network call;
- runtime contains no shell/dynamic-code execution;
- credential terms occur only in typed internal auth/redaction handling and never in logs/evidence/report templates;
- any token-shaped value is confined to explicit synthetic tests.

Inspect every match rather than suppressing the scan.

- [ ] **Step 2: Check formatting, lockfile, and diff integrity**

Run:

```bash
pnpm exec prettier --check .
git diff --check main...HEAD
git status --short
git diff --stat main...HEAD
```

Expected: formatter and diff check exit `0`; only intended files appear; the worktree is clean after any verified fix commit.

- [ ] **Step 3: Run focused security regression suites**

```bash
pnpm --filter @aegishub/bounty-core test
pnpm --filter @aegishub/bounty-runtime exec vitest run test/integration
pnpm --filter aegishub exec vitest run test/bounty-command.test.ts test/existing-command-regression.test.ts
```

Expected: all exit `0`. Record test counts and durations for the handoff.

- [ ] **Step 4: Run the exact monorepo completion gate**

```bash
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
cargo test --manifest-path packages/core/Cargo.toml
pnpm test
pnpm build
```

Expected: all exit `0`. `pnpm test` reports the live test skipped because `AEGISHUB_BOUNTY_LIVE` is not `1`.

- [ ] **Step 5: Verify a synthetic evidence bundle independently**

Run the loopback safe integration fixture with its output retained in a temporary directory, then:

1. parse every JSON and NDJSON file with the public schemas;
2. recompute every checksum;
3. verify `candidate.json` is absent for `expected`;
4. recursively search for all seeded token, device-code, email, and marker-nonce fixture values;
5. verify no absolute local path or loopback base URL appears;
6. inspect `report.md` and `reproduce.md` for accurate evidence citations.

Run the synthetic bypass fixture and verify `candidate.json` exists, cites two consistent researcher observations plus owner verification, and still contains no severity claim or secret.

- [ ] **Step 6: Map every acceptance criterion to evidence**

Use this matrix:

| # | Acceptance criterion | Required proof |
|---:|---|---|
| 1 | Existing scanner preserved | CLI regression test + Rust test + build |
| 2 | Two Device Flow actors | Device Flow unit/integration tests; optional live gate |
| 3 | Same account rejected | identity-manager and integration tests |
| 4 | No token leakage | redaction properties + console/bundle recursive scans |
| 5 | Immutable IDs and marker required | lab verifier and mismatch integration tests |
| 6 | No arbitrary host/endpoint/repo | catalog property tests + transport route assertions |
| 7 | All budgets enforced | budget properties + limiter/timeout/retry tests |
| 8 | Interactive journaled mutations | planner approval + runner journal tests |
| 9 | Policy blocks mutations/active runs | policy truth table + integration fault |
| 10 | Known-safe low-volume live experiment | opt-in live test with user present |
| 11 | Known-safe result is `expected` | built-in and full safe integration tests |
| 12 | Synthetic bypass is `anomalous` | bypass integration + candidate assertions |
| 13 | Cleanup failure dirties lab | lost/failed cleanup integration tests |
| 14 | Stable sanitized evidence | schema/checksum/atomic/redaction tests |
| 15 | Complete quality gate | Step 4 command outputs |

Do not mark criterion 10 complete until the user-owned live lab test actually succeeds. All other criteria must be proven without production access.

- [ ] **Step 7: Perform code review**

Invoke `superpowers:requesting-code-review`. Review the entire `main...HEAD` diff against the approved design and this matrix, prioritizing:

- bypasses around operation purpose or manifest checks;
- credentials crossing module or serialization boundaries;
- retrying non-idempotent mutations;
- failure paths that skip cleanup;
- evidence written before redaction;
- CLI options that silently raise authority or budgets;
- platform-specific keyring/path behavior;
- false-positive anomaly promotion.

If reviewer delegation has not been explicitly authorized for the execution session, perform the same checklist as a documented self-review and ask the user before spawning a reviewer.

- [ ] **Step 8: Fix only verified review findings and rerun affected gates**

For each finding, add or tighten a failing regression test first. Commit cohesive fixes:

```bash
git add packages/bounty-core packages/bounty-runtime packages/cli docs .github .gitignore .env.example pnpm-lock.yaml
git commit -m "fix(bounty): address completion review findings"
```

Skip this commit when review finds no defect. Never batch unrelated user files.

- [ ] **Step 9: Complete the live gate or record the single blocker**

When the user is present, follow Task 12 Step 6. If the live gate passes, attach only sanitized run ID, result state, operation count, and checksum verification to the handoff.

If it cannot run because the user has not yet created/authorized the App or lab, create `docs/superpowers/baselines/2026-08-13-bounty-mode-live-gate.md` containing only:

- exact pending prerequisite;
- safe command to resume;
- expected result;
- statement that no credentials should be sent in chat.

Do not claim full Phase 1 completion while criterion 10 is pending.

- [ ] **Step 10: Prepare the branch handoff**

Run:

```bash
git status --short
git log --oneline --decorate main..HEAD
git diff --name-status main...HEAD
```

Expected: clean worktree and reviewable focused commits. Invoke `superpowers:finishing-a-development-branch` and let the user choose whether to keep the branch, open a draft PR, or integrate it. Do not merge, publish a vulnerability, or create a HackerOne report automatically.

## Plan Self-Review Checklist

- [x] Every approved Phase 1 goal appears in a task and every acceptance criterion has a named test or manual gate.
- [x] Every production network destination is a fixed reviewed constant.
- [x] Enrollment-before-manifest is handled only by a purpose-limited owner-ID verification path.
- [x] Session-only CLI use is viable because commands can perform on-demand Device Flow in the same process.
- [x] Expired-token behavior is explicit and does not smuggle in a GitHub App client secret.
- [x] Organization enrollment fails closed under the exact Phase 1 permissions.
- [x] Mutation approval, journaling, outcome verification, cleanup, dirty state, interrupt, and process-crash paths are all covered.
- [x] No task asks for a password, cookie, 2FA code, access token, refresh token, or reserve-account credential.
- [x] No task introduces autonomous exploitation, arbitrary request replay, mass scanning, disclosure, or severity assignment.
- [x] The live test is isolated from CI and cannot choose an unenrolled target.
