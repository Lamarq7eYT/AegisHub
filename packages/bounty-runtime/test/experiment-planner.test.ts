import { describe, expect, it } from 'vitest';
import type { Experiment, LabManifest, PolicyStatus } from '@aegishub/bounty-core';

import { ExperimentPlanner, PlannerError } from '../src/experiments/planner.js';

const timestamp = '2026-08-13T12:00:00.000Z';
const repository = { id: 3003, nodeId: 'R_lab_fixture', owner: 'owner-fixture', name: 'lab-fixture', fullName: 'owner-fixture/lab-fixture', markerSha256: 'a'.repeat(64) } as const;

function manifest(): LabManifest {
  return {
    schemaVersion: 1,
    labId: '95f38cca-42e2-4b7d-82e6-f13f4549b2f3',
    githubHost: 'github.com',
    owner: { id: 1001, nodeId: 'U_owner_fixture', login: 'owner-fixture' },
    researcher: { id: 2002, nodeId: 'U_researcher_fixture', login: 'researcher-fixture' },
    repositories: [{ ...repository, ownerId: 1001 }],
    approvedOperationFamilies: ['repository-read-boundary'],
    budgets: { concurrency: 1, requestsPerSecond: 1, burst: 2, maxRequests: 10, maxMutations: 0, timeoutMs: 20_000, maxReadRetries: 2, maxMutationRetries: 0 },
    retention: { maxResponseBytes: 262_144, keepRuns: 20 },
    createdAt: timestamp,
    verifiedAt: timestamp
  };
}

function experiment(overrides: Partial<Experiment> = {}): Experiment {
  return {
    schemaVersion: 1,
    id: 'bundled-access-boundary-v1',
    version: 1,
    title: 'Fixture',
    researchQuestion: 'Does access remain bounded?',
    scopeTarget: repository.fullName,
    ineligibleCategoryChecks: ['no credential attack'],
    requiredLabCapabilities: ['private-repository'],
    budgets: { concurrency: 1, requestsPerSecond: 1, burst: 2, maxRequests: 5, maxMutations: 0, timeoutMs: 20_000, maxReadRetries: 2, maxMutationRetries: 0 },
    steps: [
      { phase: 'baseline', id: 'baseline', operationId: 'github.rest.repos.get.v1', actor: 'owner', repositoryId: repository.id, parameters: { owner: repository.owner, repo: repository.name } },
      { phase: 'probe', id: 'probe-one', operationId: 'github.rest.repos.get.v1', actor: 'anonymous', repositoryId: repository.id, parameters: { owner: repository.owner, repo: repository.name } },
      { phase: 'verify', id: 'verify', operationId: 'github.rest.repos.get.v1', actor: 'owner', repositoryId: repository.id, parameters: { owner: repository.owner, repo: repository.name } },
      { phase: 'repeat', id: 'probe-two', operationId: 'github.rest.repos.get.v1', actor: 'anonymous', repositoryId: repository.id, parameters: { owner: repository.owner, repo: repository.name } },
      { phase: 'repeat', id: 'owner-repeat', operationId: 'github.rest.repos.get.v1', actor: 'owner', repositoryId: repository.id, parameters: { owner: repository.owner, repo: repository.name } }
    ],
    normalizationProfile: 'repository-v1',
    expectation: { kind: 'access-boundary', ownerSuccessStatuses: [200], untrustedDeniedStatuses: [403, 404], protectedFields: ['private'], requireOwnerRepeat: true, minimumConsistentUntrustedAttempts: 2 },
    expectedSafeOutcome: 'denied',
    anomalyCondition: 'untrusted success',
    ...overrides
  };
}

const currentPolicy: PolicyStatus = { schemaVersion: 1, policyVersion: 'github-bbp-v1', state: 'current', checkedAt: timestamp, sourceStatuses: [{ sourceId: 'rules', state: 'match', checkedAt: timestamp, observedSha256: 'a'.repeat(64) }] };

function input(overrides: Record<string, unknown> = {}) {
  return {
    experiment: experiment(),
    manifest: manifest(),
    policy: currentPolicy,
    lab: { status: 'verified' as const, manifestSha256: 'b'.repeat(64), markerSha256: repository.markerSha256 },
    policyFingerprint: 'c'.repeat(64),
    catalogFingerprint: 'd'.repeat(64),
    ...overrides
  };
}

describe('ExperimentPlanner', () => {
  it('returns a frozen immutable plan with ordered operations and exact hashes', () => {
    const plan = new ExperimentPlanner().plan(input());
    expect(plan.operations.map(({ phase }) => phase)).toEqual(['baseline', 'probe', 'verify', 'repeat', 'repeat']);
    expect(plan.operations[0]).toMatchObject({ actor: 'owner', operationId: 'github.rest.repos.get.v1', cleanupOperationId: null });
    expect(plan.planFingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(Object.isFrozen(plan)).toBe(true);
    expect(Object.isFrozen(plan.operations)).toBe(true);
    expect(JSON.stringify(plan)).not.toContain('authorization');
  });

  it.each([
    ['stale policy', { policy: { ...currentPolicy, state: 'stale' } }, 'planner_policy_blocked'],
    ['dirty lab', { lab: { status: 'dirty', manifestSha256: 'b'.repeat(64), markerSha256: repository.markerSha256 } }, 'planner_dirty_lab'],
    ['unapproved capability', { experiment: experiment({ requiredLabCapabilities: ['missing-capability'] }) }, 'planner_capability_denied'],
    ['out-of-order phases', { experiment: experiment({ steps: [experiment().steps[1]!, experiment().steps[0]!] }) }, 'planner_phase_order_invalid'],
    ['too many operations', { experiment: experiment({ budgets: { ...experiment().budgets, maxRequests: 1 } }) }, 'planner_budget_exceeded'],
    ['insufficient untrusted repeats', { experiment: experiment({ steps: experiment().steps.filter(({ id }) => id !== 'probe-two') }) }, 'planner_repeat_requirement']
  ])('rejects %s with a stable planner error', (_label, overrides, code) => {
    expect(() => new ExperimentPlanner().plan(input(overrides))).toThrowError(new PlannerError(code as never));
  });

  it('requires verified immutable repository identity and policy approval for mutation plans', () => {
    const mutation = experiment({
      budgets: { ...experiment().budgets, maxMutations: 1 },
      steps: [...experiment().steps, { phase: 'cleanup', id: 'marker-delete', operationId: 'github.rest.contents.delete-lab-marker.v1', actor: 'owner', repositoryId: repository.id, parameters: { owner: repository.owner, repo: repository.name } }]
    });
    expect(() => new ExperimentPlanner().plan(input({ experiment: mutation }))).toThrowError(new PlannerError('planner_cleanup_inverse_missing'));
    expect(() => new ExperimentPlanner().plan(input({ lab: { status: 'unverified', manifestSha256: 'b'.repeat(64), markerSha256: repository.markerSha256 }, experiment: experiment() }))).toThrowError(new PlannerError('planner_lab_unverified'));
  });
});
