import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { classifyRun, createApprovalFingerprint, type DifferentialObservation, type LabManifest, type PolicyStatus } from '@aegishub/bounty-core';

import { ExperimentLoader } from '../src/experiments/loader.js';
import { ExperimentPlanner } from '../src/experiments/planner.js';

const runtimeRoot = new globalThis.URL('..', import.meta.url).pathname.replace(/\/test\/$/u, '');

describe('bundled private contents boundary experiment', () => {
  it('loads the strict known-safe experiment by stable ID', async () => {
    const loader = new ExperimentLoader({ workspaceRoot: '/tmp/aegishub-builtin-fixture', runtimeRoot });
    const loaded = await loader.loadBuiltIn('repo.private.contents-read-boundary.v1');
    const experiment = loaded.experiment;

    expect(experiment.id).toBe('repo.private.contents-read-boundary.v1');
    expect(experiment.version).toBe(1);
    expect(experiment.purpose).toMatch(/framework validation/i);
    expect(experiment.steps.every((step) => ['github.rest.repos.get.v1', 'github.rest.contents.get-lab-marker.v1'].includes(step.operationId))).toBe(true);
    expect(experiment.steps.every((step) => step.phase !== 'cleanup')).toBe(true);
    expect(experiment.budgets.maxMutations).toBe(0);
    expect(experiment.budgets.maxRequests).toBeLessThanOrEqual(12);

    const markerAttempts = experiment.steps.filter((step) => step.operationId === 'github.rest.contents.get-lab-marker.v1');
    expect(markerAttempts.filter((step) => step.actor === 'researcher')).toHaveLength(2);
    expect(markerAttempts.filter((step) => step.actor === 'anonymous')).toHaveLength(2);
    expect(experiment.steps.filter((step) => step.actor === 'owner' && step.phase === 'repeat')).toHaveLength(2);
    expect(experiment.expectation.untrustedDeniedStatuses).toEqual(expect.arrayContaining([403, 404]));
    expect(experiment.expectation.protectedFields).toEqual(expect.arrayContaining(['marker.labId', 'marker.repositoryId']));
    expect(experiment.requiredLabCapabilities).toContain('private-repository');
    expect(experiment.ineligibleCategoryChecks).toEqual(expect.arrayContaining(['no-third-party-target']));
    expect(experiment.steps.every((step) => step.parameters.owner && typeof step.parameters.owner === 'object' && 'ref' in step.parameters.owner)).toBe(true);
  });

  it('loads the local REST/GraphQL authorization consistency experiment with no mutation or arbitrary query', async () => {
    const loader = new ExperimentLoader({ workspaceRoot: '/tmp/aegishub-builtin-fixture', runtimeRoot });
    const loaded = await loader.loadBuiltIn('repo.private.rest-graphql-authorization.v1');
    const experiment = loaded.experiment;

    expect(experiment.id).toBe('repo.private.rest-graphql-authorization.v1');
    expect(experiment.budgets.maxRequests).toBe(12);
    expect(experiment.budgets.maxMutations).toBe(0);
    expect(experiment.steps).toHaveLength(12);
    expect(experiment.steps.filter((step) => step.operationId === 'github.graphql.contents.get-lab-marker.v1')).toHaveLength(6);
    expect(experiment.steps.every((step) => !('query' in step.parameters))).toBe(true);
    expect(experiment.steps.every((step) => step.parameters.owner && typeof step.parameters.owner === 'object' && 'ref' in step.parameters.owner)).toBe(true);
  });

  it('loads the workflow permission-boundary experiment with one fixed mutation and no execution step', async () => {
    const loader = new ExperimentLoader({ workspaceRoot: '/tmp/aegishub-builtin-fixture', runtimeRoot });
    const loaded = await loader.loadBuiltIn('repo.private.workflow-write-boundary.v1');
    const experiment = loaded.experiment;

    expect(experiment.id).toBe('repo.private.workflow-write-boundary.v1');
    expect(experiment.budgets.maxRequests).toBe(5);
    expect(experiment.budgets.maxMutations).toBe(1);
    expect(experiment.steps).toHaveLength(5);
    expect(experiment.steps.filter((step) => step.operationId === 'github.rest.actions.put-lab-workflow-probe.v1')).toHaveLength(1);
    expect(experiment.steps.filter((step) => step.operationId.includes('delete'))).toHaveLength(0);
    expect(experiment.steps.every((step) => !('branch' in step.parameters))).toBe(true);
    expect(experiment.steps.find((step) => step.operationId === 'github.rest.actions.put-lab-workflow-probe.v1')?.parameters.content).toBe('eA==');
  });

  it('keeps identical parsed documents stable and changes approval fingerprints after semantic edits', async () => {
    const workspace = await mkdtemp('/tmp/aegishub-builtin-fingerprint-');
    const directory = join(workspace, '.aegishub', 'experiments');
    await mkdir(directory, { recursive: true });
    const source = await readFile(join(runtimeRoot, 'experiments', 'repo.private.contents-read-boundary.v1.yaml'), 'utf8');
    const firstPath = join(directory, 'first.yaml');
    const secondPath = join(directory, 'second.yaml');
    const changedPath = join(directory, 'changed.yaml');
    await writeFile(firstPath, source);
    await writeFile(secondPath, source);
    await writeFile(changedPath, source.replace('maxRequests: 12', 'maxRequests: 11'));
    const loader = new ExperimentLoader({ workspaceRoot: workspace, runtimeRoot });
    const first = await loader.load(firstPath);
    const second = await loader.load(secondPath);
    const changed = await loader.load(changedPath);
    expect(first.sha256).toBe(second.sha256);
    expect(changed.sha256).not.toBe(first.sha256);

    const plan = { schemaVersion: 1 as const, planId: '3e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12', experimentId: first.experiment.id, experimentVersion: first.experiment.version, budgets: first.experiment.budgets, operations: [] };
    const changedPlan = { ...plan, budgets: changed.experiment.budgets };
    const common = { ownerId: 1001, researcherId: 2002, manifestSha256: 'a'.repeat(64), policyFingerprint: 'b'.repeat(64), catalogFingerprint: 'c'.repeat(64) };
    expect(createApprovalFingerprint({ ...common, plan })).not.toBe(createApprovalFingerprint({ ...common, plan: changedPlan }));
  });

  it('classifies scripted safe and synthetic-bypass outcomes fail-closed', () => {
    const base = {
      schemaVersion: 1 as const,
      runId: '3e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12',
      experimentId: 'repo.private.contents-read-boundary.v1',
      experimentVersion: 1,
      repositoryId: 3003,
      observedAt: '2026-08-13T12:00:00.000Z',
      durationMs: 2,
      method: 'GET' as const,
      endpointTemplate: '/repos/{owner}/{repo}',
      parameters: { owner: 'owner-fixture', repo: 'lab-fixture' },
      headers: { 'content-type': 'application/json' },
      bodySha256: 'a'.repeat(64),
      policyVersion: 'policy-v1',
      catalogVersion: '1',
      outOfLab: false
    };
    const observation = (observationId: string, actor: DifferentialObservation['actor'], status: number, repeatGroup: string, protectedData: boolean, normalizedBody: Record<string, unknown>): DifferentialObservation => ({
      ...base,
      observationId,
      operationId: actor === 'owner' ? 'github.rest.repos.get.v1' : 'github.rest.contents.get-lab-marker.v1',
      actor,
      status,
      repeatGroup,
      protectedData,
      normalizedBody: normalizedBody as import('@aegishub/bounty-core').JsonValue
    });
    const expectation = { kind: 'access-boundary' as const, ownerSuccessStatuses: [200], untrustedDeniedStatuses: [403, 404], protectedFields: ['marker.labId', 'marker.repositoryId'], requireOwnerRepeat: true as const, minimumConsistentUntrustedAttempts: 2 };
    const policy = { allowed: true };
    const owner = (id: string) => observation(id, 'owner', 200, 'owner-repository', false, { private: true });
    const denied = (id: string, actor: 'researcher' | 'anonymous' = 'researcher') => observation(id, actor, 404, `${actor}-marker`, false, { message: 'not found' });
    const disclosed = (id: string) => observation(id, 'researcher', 200, 'researcher-marker', true, { marker: { labId: '95f38cca-42e2-4b7d-82e6-f13f4549b2f3', repositoryId: 3003 } });

    const expected = classifyRun({ observations: [owner('5e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12'), owner('6e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12'), denied('7e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12'), denied('8e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12')], expectation, policy, cleanupStatus: 'not-required', independentVerification: true, impact: { kind: 'confidentiality', summary: 'Synthetic lab-owned marker.', labOwned: true }, ineligibleClasses: [] });
    expect(expected.state).toBe('expected');
    expect(expected.candidate).toBeUndefined();

    const precondition = classifyRun({ observations: [owner('9e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12'), owner('ae7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12'), observation('be7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12', 'researcher', 200, 'researcher-repository', false, { permissions: { pull: true } })], expectation, policy, cleanupStatus: 'not-required', independentVerification: true, impact: { kind: 'confidentiality', summary: 'Synthetic lab-owned marker.', labOwned: true }, ineligibleClasses: ['precondition_not_met'] });
    expect(precondition).toMatchObject({ state: 'inconclusive', reason: 'precondition_not_met' });

    const anomalous = classifyRun({ observations: [owner('ce7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12'), owner('de7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12'), disclosed('ee7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12'), disclosed('fe7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12')], expectation, policy, cleanupStatus: 'not-required', independentVerification: true, impact: { kind: 'confidentiality', summary: 'Synthetic lab-owned marker.', labOwned: true }, ineligibleClasses: [] });
    expect(anomalous.state).toBe('anomalous');
    expect(anomalous.candidate).toBeDefined();

    const mixed = classifyRun({ observations: [owner('0e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12'), owner('1e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12'), disclosed('2e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12'), denied('3e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12')], expectation, policy, cleanupStatus: 'not-required', independentVerification: true, impact: { kind: 'confidentiality', summary: 'Synthetic lab-owned marker.', labOwned: true }, ineligibleClasses: [] });
    expect(mixed).toMatchObject({ state: 'inconclusive', reason: 'protected-data-repeat-incomplete' });

    const outOfLab = classifyRun({ observations: [owner('4e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12'), { ...denied('5e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12'), outOfLab: true }], expectation, policy, cleanupStatus: 'not-required', independentVerification: true, impact: { kind: 'confidentiality', summary: 'Synthetic lab-owned marker.', labOwned: true }, ineligibleClasses: [] });
    expect(outOfLab).toMatchObject({ state: 'inconclusive', reason: 'out_of_lab_resource' });
  });

  it('resolves only typed lab references before planning catalog operations', async () => {
    const loader = new ExperimentLoader({ workspaceRoot: '/tmp/aegishub-builtin-fixture', runtimeRoot });
    const loaded = await loader.loadBuiltIn('repo.private.contents-read-boundary.v1');
    const timestamp = '2026-08-13T12:00:00.000Z';
    const manifest: LabManifest = {
      schemaVersion: 1,
      labId: '95f38cca-42e2-4b7d-82e6-f13f4549b2f3',
      githubHost: 'github.com',
      owner: { id: 1001, nodeId: 'U_owner_fixture', login: 'owner-fixture' },
      researcher: { id: 2002, nodeId: 'U_researcher_fixture', login: 'researcher-fixture' },
      repositories: [{ id: 3003, nodeId: 'R_lab_fixture', ownerId: 1001, owner: 'owner-fixture', name: 'lab-fixture', fullName: 'owner-fixture/lab-fixture', markerSha256: 'a'.repeat(64) }],
      approvedOperationFamilies: ['repository-read-boundary'],
      budgets: { concurrency: 1, requestsPerSecond: 1, burst: 2, maxRequests: 12, maxMutations: 0, timeoutMs: 20_000, maxReadRetries: 2, maxMutationRetries: 0 },
      retention: { maxResponseBytes: 262_144, keepRuns: 20 },
      createdAt: timestamp,
      verifiedAt: timestamp
    };
    const policy: PolicyStatus = { schemaVersion: 1, policyVersion: 'policy-v1', state: 'current', checkedAt: timestamp, sourceStatuses: [{ sourceId: 'roe', state: 'match', checkedAt: timestamp, observedSha256: 'b'.repeat(64) }]     };
    const plan = new ExperimentPlanner().plan({
      experiment: loaded.experiment,
      manifest,
      policy,
      lab: { status: 'verified', manifestSha256: 'c'.repeat(64), markerSha256: 'a'.repeat(64) },
      policyFingerprint: 'd'.repeat(64),
      catalogFingerprint: 'e'.repeat(64)
    });
    expect(plan.operations).toHaveLength(10);
    expect(plan.operations.every((operation) => operation.parameters.owner === 'owner-fixture' && operation.parameters.repo === 'lab-fixture')).toBe(true);
    expect(plan.operations.some((operation) => operation.actor === 'researcher')).toBe(true);
  });
});
