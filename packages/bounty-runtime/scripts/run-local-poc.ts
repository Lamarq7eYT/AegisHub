import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

import {
  type BoundaryExpectation,
  createApprovalGrant,
  type ExperimentPlan,
  type LabManifest,
  type PlannedExperimentOperation,
  type PolicyStatus,
  type PlannedOperation
} from '@aegishub/bounty-core';

import { LabStore } from '../src/lab/store.js';
import { ExperimentRunner } from '../src/experiments/runner.js';
import { GuardedGitHubTransport } from '../src/transport/guarded-transport.js';
import { RunRateLimiter } from '../src/transport/rate-limiter.js';
import { FakeGithubServer } from '../test/support/fake-github-server.js';

const labId = '95f38cca-42e2-4b7d-82e6-f13f4549b2f3';
const repository = { id: 3003, nodeId: 'R_lab', fullName: 'owner-fixture/lab-fixture' } as const;
const now = new Date('2026-08-15T20:00:00.000Z');
const expectation: BoundaryExpectation = {
  kind: 'access-boundary',
  ownerSuccessStatuses: [200],
  untrustedDeniedStatuses: [403, 404],
  protectedFields: ['marker.schemaVersion', 'marker.labId', 'marker.repositoryId'],
  requireOwnerRepeat: true,
  minimumConsistentUntrustedAttempts: 2
};
const policy: PolicyStatus = {
  schemaVersion: 1,
  policyVersion: 'local-poc-policy-v1',
  state: 'current',
  checkedAt: now.toISOString(),
  sourceStatuses: [{ sourceId: 'local-loopback', state: 'match', checkedAt: now.toISOString(), observedSha256: 'b'.repeat(64) }]
};
const manifest: LabManifest = {
  schemaVersion: 1,
  labId,
  githubHost: 'github.com',
  owner: { id: 1001, nodeId: 'U_owner_fixture', login: 'owner-fixture' },
  researcher: { id: 2002, nodeId: 'U_researcher_fixture', login: 'researcher-fixture' },
  repositories: [{ id: 3003, nodeId: 'R_lab', ownerId: 1001, owner: 'owner-fixture', name: 'lab-fixture', fullName: 'owner-fixture/lab-fixture', markerSha256: 'a'.repeat(64) }],
  approvedOperationFamilies: ['repository-read-boundary'],
  budgets: { concurrency: 1, requestsPerSecond: 1, burst: 2, maxRequests: 12, maxMutations: 0, timeoutMs: 20_000, maxReadRetries: 2, maxMutationRetries: 0 },
  retention: { maxResponseBytes: 262_144, keepRuns: 20 },
  createdAt: now.toISOString(),
  verifiedAt: now.toISOString()
};

type LocalPlan = ExperimentPlan & {
  readonly planFingerprint: string;
  readonly manifestSha256: string;
  readonly policyFingerprint: string;
  readonly catalogFingerprint: string;
  readonly labId: string;
};

type Mode = 'safe' | 'bypass';

function operation(
  ordinal: number,
  phase: PlannedExperimentOperation['phase'],
  actor: PlannedExperimentOperation['actor'],
  stepId: string,
  operationId: PlannedExperimentOperation['operationId']
): PlannedExperimentOperation {
  return {
    ordinal,
    phase,
    stepId,
    actor,
    operationId,
    parameters: { owner: 'owner-fixture', repo: 'lab-fixture' },
    expectedEffect: 'read-only observation',
    cleanupOperationId: null
  };
}

function plan(runId: string): LocalPlan {
  return {
    schemaVersion: 1,
    planId: runId,
    experimentId: 'repo.private.rest-graphql-authorization.v1',
    experimentVersion: 1,
    budgets: manifest.budgets,
    operations: [
      operation(1, 'baseline', 'owner', 'owner-baseline', 'github.rest.contents.get-lab-marker.v1'),
      operation(2, 'probe', 'researcher', 'researcher-probe-1', 'github.rest.contents.get-lab-marker.v1'),
      operation(3, 'repeat', 'researcher', 'researcher-probe-2', 'github.rest.contents.get-lab-marker.v1'),
      operation(4, 'repeat', 'owner', 'owner-repeat', 'github.rest.contents.get-lab-marker.v1'),
      operation(5, 'verify', 'owner', 'must-not-run-after-candidate', 'github.graphql.contents.get-lab-marker.v1')
    ],
    planFingerprint: 'a'.repeat(64),
    manifestSha256: 'c'.repeat(64),
    policyFingerprint: 'b'.repeat(64),
    catalogFingerprint: 'd'.repeat(64),
    labId
  };
}

function toPlannedOperation(operation: {
  readonly stepId: string;
  readonly phase: PlannedExperimentOperation['phase'];
  readonly actor: PlannedExperimentOperation['actor'];
  readonly operationId: string;
  readonly parameters: Record<string, import('@aegishub/bounty-core').JsonValue>;
}, planValue: LocalPlan): PlannedOperation {
  return {
    schemaVersion: 1,
    planId: planValue.planId,
    plannedAt: now.toISOString(),
    labId,
    experimentId: planValue.experimentId,
    experimentVersion: planValue.experimentVersion,
    step: {
      id: operation.stepId,
      phase: operation.phase,
      actor: operation.actor,
      operationId: operation.operationId as PlannedOperation['step']['operationId'],
      repositoryId: repository.id,
      parameters: operation.parameters,
      repeatGroup: operation.actor === 'owner' ? 'owner-marker' : 'researcher-marker'
    }
  };
}

function transport(server: FakeGithubServer, runId: string): GuardedGitHubTransport {
  return new GuardedGitHubTransport({
    executor: server.executor(),
    tokenProvider: { getUsableToken: async (actor) => actor === 'owner' ? 'owner-token' : 'researcher-token' },
    rateLimiter: new RunRateLimiter({ concurrency: 1, requestsPerSecond: 100, burst: 8 }),
    budget: { maxRequests: 12, maxMutations: 0 },
    policyFingerprint: () => 'b'.repeat(64),
    expectedPolicyFingerprint: 'b'.repeat(64),
    context: { labId, runId, policyVersion: policy.policyVersion, catalogVersion: '1.1.0', repository }
  });
}

async function runMode(mode: Mode): Promise<{
  readonly mode: Mode;
  readonly result: string;
  readonly reason?: string;
  readonly requestCount: number;
  readonly mutationCount: number;
  readonly cleanupStatus: string;
  readonly candidate: boolean;
  readonly candidateReproductionCount?: number;
  readonly protectedUntrustedObservations: number;
  readonly stoppedBeforeFollowUp: boolean;
}> {
  const server = new FakeGithubServer({ bypass: mode === 'bypass' });
  await server.start();
  const runId = randomUUID();
  const currentPlan = plan(runId);
  const store = new LabStore(await mkdtemp(join(tmpdir(), 'aegishub-local-poc-')));
  try {
    const completed = await new ExperimentRunner().run({
      store,
      runId,
      labId,
      repository,
      plan: currentPlan,
      policy,
      policyFingerprint: () => 'b'.repeat(64),
      expectedPolicyFingerprint: 'b'.repeat(64),
      catalogFingerprint: 'd'.repeat(64),
      interactiveTerminal: true,
      approvalGrant: createApprovalGrant(currentPlan.planFingerprint, now),
      expectation,
      impact: { kind: 'confidentiality', summary: 'Synthetic lab-owned marker content.', labOwned: true },
      ineligibleClasses: [],
      executor: {
        execute: async (operation, signal) => transport(server, runId).execute(toPlannedOperation(operation, currentPlan), signal)
      },
      now: () => now
    });
    const protectedUntrustedObservations = completed.observations.filter((observation) => observation.actor !== 'owner' && observation.protectedData).length;
    return {
      mode,
      result: completed.manifest.result,
      ...(completed.reason === undefined ? {} : { reason: completed.reason }),
      requestCount: completed.manifest.requestCount,
      mutationCount: completed.manifest.mutationCount,
      cleanupStatus: completed.manifest.cleanupStatus,
      candidate: completed.candidate !== undefined,
      ...(completed.candidate === undefined ? {} : { candidateReproductionCount: completed.candidate.reproductionCount }),
      protectedUntrustedObservations,
      stoppedBeforeFollowUp: !server.requests.some((request) => request.operationId === 'github.graphql.contents.get-lab-marker.v1')
    };
  } finally {
    await server.stop();
  }
}

function markdown(results: readonly Awaited<ReturnType<typeof runMode>>[]): string {
  const lines = [
    '# AegisHub Phase 2 — local REST/GraphQL PoC',
    '',
    '> Loopback-only demonstration using the checked-in fake GitHub server. It did not contact GitHub, use real credentials, or claim severity.',
    '',
    '| Mode | Result | Requests | Mutations | Protected untrusted observations | Candidate | Candidate repetitions |',
    '| --- | --- | ---: | ---: | ---: | --- | ---: |'
  ];
  for (const result of results) {
    lines.push(`| ${result.mode} | ${result.result} | ${result.requestCount} | ${result.mutationCount} | ${result.protectedUntrustedObservations} | ${result.candidate ? 'yes' : 'no'} | ${result.candidateReproductionCount ?? '—'} |`);
  }
  lines.push('', 'The bypass case is synthetic and exists only to prove the high candidate threshold: two repeated protected marker disclosures are required, then the runner stops before the follow-up GraphQL operation. Cosmetic differences do not become candidates.', '');
  return lines.join('\n');
}

const results = [await runMode('safe'), await runMode('bypass')];
const output = {
  schemaVersion: 1,
  scope: 'loopback-fake-server-only',
  generatedAt: now.toISOString(),
  results,
  noSeverityClaim: true,
  noLiveExecution: true
};
const outIndex = globalThis.process.argv.indexOf('--out');
const outPath = outIndex >= 0 ? globalThis.process.argv[outIndex + 1] : undefined;
if (outPath === undefined) {
  globalThis.process.stdout.write(`${JSON.stringify(output, null, 2)}\n\n${markdown(results)}`);
} else {
  const { mkdir, writeFile } = await import('node:fs/promises');
  await mkdir(outPath, { recursive: true });
  await writeFile(join(outPath, 'summary.json'), `${JSON.stringify(output, null, 2)}\n`, { mode: 0o600 });
  await writeFile(join(outPath, 'report.md'), markdown(results), { mode: 0o600 });
  globalThis.process.stdout.write(`local_poc_output=${outPath}\n`);
}
