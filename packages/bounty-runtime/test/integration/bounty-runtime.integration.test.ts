import { mkdtemp } from 'node:fs/promises';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';
import {
  classifyRun,
  type BoundaryExpectation,
  type DifferentialObservation,
  type LabManifest,
  type PlannedOperation,
  type PolicyStatus
} from '@aegishub/bounty-core';

import { AtomicEvidenceWriter } from '../../src/evidence/writer.js';
import { ExperimentLoader } from '../../src/experiments/loader.js';
import { ExperimentPlanner } from '../../src/experiments/planner.js';
import { GuardedGitHubTransport } from '../../src/transport/guarded-transport.js';
import { RunRateLimiter } from '../../src/transport/rate-limiter.js';
import { FakeGithubServer } from '../support/fake-github-server.js';

const labId = '95f38cca-42e2-4b7d-82e6-f13f4549b2f3';
const runId = '3e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12';
const expectation: BoundaryExpectation = {
  kind: 'access-boundary',
  ownerSuccessStatuses: [200],
  untrustedDeniedStatuses: [403, 404],
  protectedFields: ['marker.labId', 'marker.repositoryId'],
  requireOwnerRepeat: true,
  minimumConsistentUntrustedAttempts: 2
};

let server: FakeGithubServer | undefined;

afterEach(async () => {
  await server?.stop();
  server = undefined;
});

describe('bounty runtime loopback integration', () => {
  it('runs the safe boundary with exact planned request count and expected classification', async () => {
    server = new FakeGithubServer();
    await server.start();
    const transport = makeTransport(server);
    const observations = await Promise.all([
      transport.execute(operation('owner-read-1', 'owner', 'owner-baseline', 'github.rest.repos.get.v1'), new globalThis.AbortController().signal),
      transport.execute(operation('owner-read-2', 'owner', 'owner-baseline', 'github.rest.repos.get.v1'), new globalThis.AbortController().signal),
      transport.execute(operation('researcher-marker-1', 'researcher', 'researcher-marker', 'github.rest.contents.get-lab-marker.v1'), new globalThis.AbortController().signal),
      transport.execute(operation('researcher-marker-2', 'researcher', 'researcher-marker', 'github.rest.contents.get-lab-marker.v1'), new globalThis.AbortController().signal)
    ]) as unknown as DifferentialObservation[];
    const result = classifyRun({
      observations,
      expectation,
      policy: { allowed: true },
      cleanupStatus: 'not-required',
      independentVerification: true,
      impact: { kind: 'confidentiality', summary: 'Synthetic lab-owned marker.', labOwned: true },
      ineligibleClasses: []
    });
    expect(result.state).toBe('expected');
    expect(result.candidate).toBeUndefined();
    expect(server.requests).toHaveLength(4);
    expect(server.requests.every((request) => !JSON.stringify(request).includes('owner-token'))).toBe(true);
    expect(server.requests.every((request) => !JSON.stringify(request).includes('researcher-token'))).toBe(true);
    expect(server.requests.map((request) => request.operationId)).toEqual([
      'github.rest.repos.get.v1',
      'github.rest.repos.get.v1',
      'github.rest.contents.get-lab-marker.v1',
      'github.rest.contents.get-lab-marker.v1'
    ]);
  });

  it('compares REST and GraphQL boundaries in the loopback PoC without promoting cosmetic differences', async () => {
    server = new FakeGithubServer();
    await server.start();
    const transport = makeTransport(server);
    const steps: Array<[string, 'owner' | 'researcher' | 'anonymous', string, PlannedOperation['step']['operationId']]> = [
      ['owner-rest', 'owner', 'owner-rest', 'github.rest.contents.get-lab-marker.v1'],
      ['owner-graphql', 'owner', 'owner-graphql', 'github.graphql.contents.get-lab-marker.v1'],
      ['researcher-rest-1', 'researcher', 'researcher-rest', 'github.rest.contents.get-lab-marker.v1'],
      ['researcher-rest-2', 'researcher', 'researcher-rest', 'github.rest.contents.get-lab-marker.v1'],
      ['researcher-graphql-1', 'researcher', 'researcher-graphql', 'github.graphql.contents.get-lab-marker.v1'],
      ['researcher-graphql-2', 'researcher', 'researcher-graphql', 'github.graphql.contents.get-lab-marker.v1'],
      ['anonymous-rest-1', 'anonymous', 'anonymous-rest', 'github.rest.contents.get-lab-marker.v1'],
      ['anonymous-rest-2', 'anonymous', 'anonymous-rest', 'github.rest.contents.get-lab-marker.v1'],
      ['anonymous-graphql-1', 'anonymous', 'anonymous-graphql', 'github.graphql.contents.get-lab-marker.v1'],
      ['anonymous-graphql-2', 'anonymous', 'anonymous-graphql', 'github.graphql.contents.get-lab-marker.v1'],
      ['owner-rest-repeat', 'owner', 'owner-rest', 'github.rest.contents.get-lab-marker.v1'],
      ['owner-graphql-repeat', 'owner', 'owner-graphql', 'github.graphql.contents.get-lab-marker.v1']
    ];
    const observations: DifferentialObservation[] = [];
    for (const [id, actor, repeatGroup, operationId] of steps) {
      observations.push(await transport.execute(operation(id, actor, repeatGroup, operationId), new globalThis.AbortController().signal) as unknown as DifferentialObservation);
    }
    const result = classifyRun({ observations, expectation, policy: { allowed: true }, cleanupStatus: 'not-required', independentVerification: true, impact: { kind: 'confidentiality', summary: 'Synthetic lab-owned marker.', labOwned: true }, ineligibleClasses: [] });

    expect(result.state).toBe('expected');
    expect(result.candidate).toBeUndefined();
    expect(observations.filter((observation) => observation.actor !== 'owner').every((observation) => !observation.protectedData)).toBe(true);
    expect(observations.filter((observation) => observation.operationId === 'github.graphql.contents.get-lab-marker.v1')).toHaveLength(6);
    expect(server.requests).toHaveLength(12);
    expect(server.requests.every((request) => !JSON.stringify(request).includes('synthetic-control-nonce'))).toBe(true);
  });

  it('denies researcher boundary writes without changing the lab marker', async () => {
    server = new FakeGithubServer();
    await server.start();
    const writeOperation = operation('researcher-write', 'researcher', 'researcher-write', 'github.rest.contents.put-lab-boundary-marker.v1' as never);
    writeOperation.step.parameters = {
      owner: 'owner-fixture',
      repo: 'lab-fixture',
      message: 'aegishub: verify bounty lab',
      content: 'eyJmaXh0dXJlIjp0cnVlfQ=='
    };
    const observation = await makeTransport(server, 1).execute(writeOperation, new globalThis.AbortController().signal);

    expect(observation.status).toBe(403);
    expect(observation.errorClass).toBe('access_denied');
    expect(server.markerPresent).toBe(false);
    expect(server.requests).toMatchObject([{ operationId: 'github.rest.contents.put-lab-boundary-marker.v1', actor: 'researcher', method: 'PUT' }]);
  });

  it('produces a real lab-owned candidate in loopback only when bypass discloses protected data twice', async () => {
    server = new FakeGithubServer({ bypass: true });
    await server.start();
    const transport = makeTransport(server);
    const observations = [
      await transport.execute(operation('owner-rest', 'owner', 'owner-rest', 'github.rest.contents.get-lab-marker.v1'), new globalThis.AbortController().signal),
      await transport.execute(operation('owner-graphql', 'owner', 'owner-graphql', 'github.graphql.contents.get-lab-marker.v1'), new globalThis.AbortController().signal),
      await transport.execute(operation('researcher-rest-1', 'researcher', 'researcher-rest', 'github.rest.contents.get-lab-marker.v1'), new globalThis.AbortController().signal),
      await transport.execute(operation('researcher-rest-2', 'researcher', 'researcher-rest', 'github.rest.contents.get-lab-marker.v1'), new globalThis.AbortController().signal),
      await transport.execute(operation('owner-rest-repeat', 'owner', 'owner-rest', 'github.rest.contents.get-lab-marker.v1'), new globalThis.AbortController().signal),
      await transport.execute(operation('owner-graphql-repeat', 'owner', 'owner-graphql', 'github.graphql.contents.get-lab-marker.v1'), new globalThis.AbortController().signal)
    ] as DifferentialObservation[];
    const result = classifyRun({ observations, expectation, policy: { allowed: true }, cleanupStatus: 'not-required', independentVerification: true, impact: { kind: 'confidentiality', summary: 'Synthetic lab-owned marker was disclosed to an untrusted actor.', labOwned: true }, ineligibleClasses: [] });

    expect(result.state).toBe('anomalous');
    expect(result.candidate).toMatchObject({ reproductionCount: 2, knownIneligible: false, cleanupStatus: 'complete' });
    expect(result.candidate?.impact.summary).toContain('Synthetic lab-owned marker');
    expect(server.requests).toHaveLength(6);
  });

  it('persists, verifies and exports the sanitized expected run bundle', async () => {
    server = new FakeGithubServer();
    await server.start();
    const workspaceRoot = await mkdtemp('/tmp/aegishub-runtime-integration-');
    const runtimeRoot = new globalThis.URL('../..', import.meta.url).pathname;
    const experiment = await new ExperimentLoader({ workspaceRoot, runtimeRoot }).loadBuiltIn('repo.private.contents-read-boundary.v1');
    const timestamp = '2026-08-13T12:00:00.000Z';
    const manifest = {
      schemaVersion: 1,
      labId,
      githubHost: 'github.com',
      owner: { id: 1001, nodeId: 'U_owner_fixture', login: 'owner-fixture' },
      researcher: { id: 2002, nodeId: 'U_researcher_fixture', login: 'researcher-fixture' },
      repositories: [{ id: 3003, nodeId: 'R_lab_fixture', ownerId: 1001, owner: 'owner-fixture', name: 'lab-fixture', fullName: 'owner-fixture/lab-fixture', markerSha256: 'a'.repeat(64) }],
      approvedOperationFamilies: ['repository-read-boundary'],
      budgets: { concurrency: 1, requestsPerSecond: 1, burst: 2, maxRequests: 12, maxMutations: 0, timeoutMs: 20_000, maxReadRetries: 2, maxMutationRetries: 0 },
      retention: { maxResponseBytes: 262_144, keepRuns: 20 },
      createdAt: timestamp,
      verifiedAt: timestamp
    } satisfies LabManifest;
    const policy = { schemaVersion: 1, policyVersion: 'policy-v1', state: 'current', checkedAt: timestamp, sourceStatuses: [{ sourceId: 'rules', state: 'match', checkedAt: timestamp, observedSha256: 'b'.repeat(64) }] } satisfies PolicyStatus;
    const plan = new ExperimentPlanner().plan({ experiment: experiment.experiment, manifest, policy, lab: { status: 'verified', manifestSha256: 'c'.repeat(64), markerSha256: 'a'.repeat(64) }, policyFingerprint: 'd'.repeat(64), catalogFingerprint: 'e'.repeat(64) });
    const observations = await Promise.all([
      makeTransport(server).execute(operation('owner-read-1', 'owner', 'owner-baseline', 'github.rest.repos.get.v1'), new globalThis.AbortController().signal),
      makeTransport(server).execute(operation('owner-read-2', 'owner', 'owner-baseline', 'github.rest.repos.get.v1'), new globalThis.AbortController().signal),
      makeTransport(server).execute(operation('researcher-marker-1', 'researcher', 'researcher-marker', 'github.rest.contents.get-lab-marker.v1'), new globalThis.AbortController().signal),
      makeTransport(server).execute(operation('researcher-marker-2', 'researcher', 'researcher-marker', 'github.rest.contents.get-lab-marker.v1'), new globalThis.AbortController().signal)
    ]) as unknown as DifferentialObservation[];
    const classified = classifyRun({ observations, expectation, policy: { allowed: true }, cleanupStatus: 'not-required', independentVerification: true, impact: { kind: 'confidentiality', summary: 'Synthetic lab-owned marker.', labOwned: true }, ineligibleClasses: [] });
    if (classified.diff === undefined) throw new Error('integration_diff_missing');
    const writer = new AtomicEvidenceWriter({ workspaceRoot, lab: { labId, ownerId: 1001, researcherId: 2002, repository: { id: 3003, nodeId: 'R_lab_fixture', owner: 'owner-fixture', name: 'lab-fixture', fullName: 'owner-fixture/lab-fixture' }, markerSha256: 'a'.repeat(64) }, policy, policyExcerptIds: ['rules'], experiment: experiment.experiment, plan });
    const written = await writer.write({ manifest: { schemaVersion: 1, runId, labId, policyVersion: 'policy-v1', experimentId: experiment.experiment.id, experimentVersion: experiment.experiment.version, startedAt: timestamp, completedAt: timestamp, result: 'expected', requestCount: 4, mutationCount: 0, cleanupStatus: 'not-required' }, observations, diff: classified.diff, cleanupStatus: 'not-required', recovery: {} as never });
    const inspected = await writer.inspect(runId);
    const exported = await writer.export(runId, join(workspaceRoot, 'analysis-pack'));
    expect(written.files.some((file) => file.relativePath === 'checksums.txt')).toBe(true);
    expect(inspected.verified).toBe(true);
    expect(inspected.observations).toHaveLength(4);
    expect(exported.path).toContain('analysis-pack');
  });

  it('classifies the toggled synthetic authorization bypass as anomalous with lab-owned impact', async () => {
    server = new FakeGithubServer({ bypass: true });
    await server.start();
    const transport = makeTransport(server);
    const observations = await Promise.all([
      transport.execute(operation('owner-read-1', 'owner', 'owner-baseline', 'github.rest.repos.get.v1'), new globalThis.AbortController().signal),
      transport.execute(operation('owner-read-2', 'owner', 'owner-baseline', 'github.rest.repos.get.v1'), new globalThis.AbortController().signal),
      transport.execute(operation('researcher-marker-1', 'researcher', 'researcher-marker', 'github.rest.contents.get-lab-marker.v1'), new globalThis.AbortController().signal),
      transport.execute(operation('researcher-marker-2', 'researcher', 'researcher-marker', 'github.rest.contents.get-lab-marker.v1'), new globalThis.AbortController().signal)
    ]) as unknown as DifferentialObservation[];
    expect(observations.filter((observation) => observation.actor === 'researcher').every((observation) => observation.protectedData)).toBe(true);
    const result = classifyRun({
      observations,
      expectation,
      policy: { allowed: true },
      cleanupStatus: 'not-required',
      independentVerification: true,
      impact: { kind: 'confidentiality', summary: 'Protected synthetic marker from the verified lab.', labOwned: true },
      ineligibleClasses: []
    });
    expect(result.state).toBe('anomalous');
    expect(result.candidate?.evidenceIds).toHaveLength(2);
    expect(result.candidate?.impact.kind).toBe('confidentiality');
    expect(result.candidate?.impact.summary).toContain('verified lab');
    expect(result.candidate).not.toHaveProperty('severity');
  });
});

function makeTransport(fake: FakeGithubServer, maxMutations = 0): GuardedGitHubTransport {
  return new GuardedGitHubTransport({
    executor: fake.executor(),
    tokenProvider: { getUsableToken: async (actor) => actor === 'owner' ? 'owner-token' : 'researcher-token' },
    rateLimiter: new RunRateLimiter({ concurrency: 1, requestsPerSecond: 100, burst: 8 }),
    budget: { maxRequests: 12, maxMutations },
    policyFingerprint: () => 'b'.repeat(64),
    expectedPolicyFingerprint: 'b'.repeat(64),
    context: {
      labId,
      runId,
      policyVersion: 'policy-v1',
      catalogVersion: '1.0.0',
      repository: { id: 3003, nodeId: 'R_lab', fullName: 'owner-fixture/lab-fixture' }
    }
  });
}

function operation(id: string, actor: 'owner' | 'researcher' | 'anonymous', repeatGroup: string, operationId: PlannedOperation['step']['operationId']): PlannedOperation {
  return {
    schemaVersion: 1,
    planId: runId,
    plannedAt: '2026-08-13T12:00:00.000Z',
    labId,
    experimentId: 'repo.private.contents-read-boundary.v1',
    experimentVersion: 1,
    step: {
      id,
      phase: 'probe',
      actor,
      operationId,
      repositoryId: 3003,
      parameters: { owner: 'owner-fixture', repo: 'lab-fixture' },
      repeatGroup
    }
  };
}
