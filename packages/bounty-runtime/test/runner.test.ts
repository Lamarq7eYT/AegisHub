import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';
import {
  createApprovalGrant,
  type Actor,
  type Budget,
  type ExperimentPlan,
  type Observation,
  type JsonValue,
  type PlannedExperimentOperation
} from '@aegishub/bounty-core';

import { LabStore } from '../src/lab/store.js';
import {
  ExperimentRunner,
  RunnerError,
  type ExperimentExecutor,
  type RunExperimentInput
} from '../src/experiments/runner.js';

const runId = '3e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12';
const labId = '95f38cca-42e2-4b7d-82e6-f13f4549b2f3';
const repositoryId = 3003;
const now = new Date('2026-08-13T12:00:00.000Z');
const budget: Budget = {
  concurrency: 1,
  requestsPerSecond: 1,
  burst: 2,
  maxRequests: 20,
  maxMutations: 1,
  timeoutMs: 20_000,
  maxReadRetries: 2,
  maxMutationRetries: 0
};

function operation(
  ordinal: number,
  phase: PlannedExperimentOperation['phase'],
  actor: Actor,
  operationId = 'github.rest.get-repository',
  overrides: Partial<PlannedExperimentOperation> = {}
): PlannedExperimentOperation {
  return {
    ordinal,
    phase,
    stepId: `${phase}-${ordinal}`,
    actor,
    operationId,
    parameters: { owner: 'owner-fixture', repo: 'lab-fixture' },
    expectedEffect: operationId.includes('put') ? 'declared mutation with inverse cleanup' : 'read-only observation',
    cleanupOperationId: operationId.includes('put') ? 'github.rest.delete-lab-marker' : null,
    ...overrides
  };
}

function plan(operations: readonly PlannedExperimentOperation[]): ExperimentPlan & {
  readonly planFingerprint: string;
  readonly manifestSha256: string;
  readonly policyFingerprint: string;
  readonly catalogFingerprint: string;
  readonly labId: string;
} {
  return {
    schemaVersion: 1,
    planId: runId,
    experimentId: 'bundled-access-boundary-v1',
    experimentVersion: 1,
    budgets: budget,
    operations,
    planFingerprint: 'b'.repeat(64),
    manifestSha256: 'c'.repeat(64),
    policyFingerprint: 'd'.repeat(64),
    catalogFingerprint: 'e'.repeat(64),
    labId
  };
}

function observation(
  op: PlannedExperimentOperation,
  actor: Actor,
  status: number,
  body: Record<string, unknown>,
  overrides: Partial<Observation> = {}
): Observation {
  return {
    schemaVersion: 1,
    observationId: `${String(op.ordinal).padStart(8, '0')}-0000-4000-8000-000000000000`,
    runId,
    experimentId: 'bundled-access-boundary-v1',
    experimentVersion: 1,
    operationId: op.operationId as never,
    actor,
    repositoryId,
    observedAt: now.toISOString(),
    durationMs: 1,
    method: op.operationId.includes('put') ? 'PUT' : 'GET',
    endpointTemplate: '/repos/{owner}/{repo}',
    parameters: op.parameters,
    status,
    headers: { 'content-type': 'application/json' },
    normalizedBody: body as JsonValue,
    bodySha256: 'a'.repeat(64),
    repeatGroup: actor === 'owner' ? 'owner-baseline' : 'untrusted-probe',
    protectedData: false,
    outOfLab: false,
    policyVersion: 'policy-v1',
    catalogVersion: 'phase1-v1',
    ...overrides
  };
}

function baseInput(
  store: LabStore,
  experimentPlan: ReturnType<typeof plan>,
  executor: ExperimentExecutor,
  overrides: Partial<RunExperimentInput> = {}
): RunExperimentInput {
  return {
    store,
    runId,
    labId,
    repository: { id: repositoryId, nodeId: 'R_lab_fixture', fullName: 'owner-fixture/lab-fixture' },
    plan: experimentPlan,
    policy: { state: 'current', policyVersion: 'policy-v1' },
    policyFingerprint: () => 'd'.repeat(64),
    expectedPolicyFingerprint: 'd'.repeat(64),
    catalogFingerprint: 'e'.repeat(64),
    interactiveTerminal: true,
    approvalGrant: createApprovalGrant(experimentPlan.planFingerprint, now),
    expectation: {
      kind: 'access-boundary',
      ownerSuccessStatuses: [200],
      untrustedDeniedStatuses: [403, 404],
      protectedFields: ['private'],
      requireOwnerRepeat: true,
      minimumConsistentUntrustedAttempts: 2
    },
    impact: { kind: 'confidentiality', summary: 'synthetic lab-only fixture', labOwned: true },
    ineligibleClasses: [],
    executor,
    now: () => now,
    ...overrides
  };
}

class ScriptedExecutor implements ExperimentExecutor {
  readonly calls: PlannedExperimentOperation[] = [];
  constructor(private readonly script: (operation: PlannedExperimentOperation, call: number) => Promise<Observation> | Observation) {}
  async execute(operation: PlannedExperimentOperation): Promise<Observation> {
    this.calls.push(operation);
    return this.script(operation, this.calls.length);
  }
}

describe('ExperimentRunner', () => {
  it('executes phases in order and classifies a clean safe boundary as expected', async () => {
    const store = new LabStore(await mkdtemp(join(tmpdir(), 'aegishub-runner-')));
    const operations = [
      operation(1, 'baseline', 'owner', 'github.rest.get-repository', { stepId: 'owner-baseline' }),
      operation(2, 'probe', 'anonymous', 'github.rest.get-repository', { stepId: 'untrusted-1' }),
      operation(3, 'repeat', 'anonymous', 'github.rest.get-repository', { stepId: 'untrusted-2' }),
      operation(4, 'repeat', 'owner', 'github.rest.get-repository', { stepId: 'owner-repeat' })
    ];
    const executor = new ScriptedExecutor((op) => observation(op, op.actor, op.actor === 'owner' ? 200 : 403, { private: op.actor === 'owner' }));

    const completed = await new ExperimentRunner().run(baseInput(store, plan(operations), executor));

    expect(executor.calls.map((call) => call.phase)).toEqual(['baseline', 'probe', 'repeat', 'repeat']);
    expect(completed.manifest.result).toBe('expected');
    expect(completed.cleanupStatus).toBe('not-required');
  });

  it('does not reach transport for a mutation without interactive approval', async () => {
    const store = new LabStore(await mkdtemp(join(tmpdir(), 'aegishub-runner-')));
    const mutation = operation(1, 'setup', 'owner', 'github.rest.put-lab-marker');
    const executor = new ScriptedExecutor((op) => observation(op, op.actor, 200, {}));

    const withApproval = baseInput(store, plan([mutation]), executor, { interactiveTerminal: false });
    const withoutApproval = { ...withApproval };
    delete withoutApproval.approvalGrant;
    await expect(new ExperimentRunner().run(withoutApproval)).rejects.toEqual(new RunnerError('runner_approval_required'));
    expect(executor.calls).toHaveLength(0);
  });

  it('writes ahead, verifies a lost mutation response, and never replays the mutation', async () => {
    const store = new LabStore(await mkdtemp(join(tmpdir(), 'aegishub-runner-')));
    const mutation = operation(1, 'setup', 'owner', 'github.rest.put-lab-marker');
    const executor = new ScriptedExecutor(async () => {
      throw Object.assign(new Error('network lost'), { code: 'transport_mutation_outcome_unknown' });
    });

    const completed = await new ExperimentRunner().run(baseInput(store, plan([mutation]), executor, {
      verifyMutation: async () => ({ applied: false, evidenceId: 'verification-not-applied' })
    }));

    expect(executor.calls).toHaveLength(1);
    expect(completed.manifest.result).toBe('inconclusive');
    expect(completed.cleanupStatus).toBe('complete');
  });

  it('runs inverse cleanup after a verified mutation and marks dirty when cleanup cannot be verified', async () => {
    const store = new LabStore(await mkdtemp(join(tmpdir(), 'aegishub-runner-')));
    const mutation = operation(1, 'setup', 'owner', 'github.rest.put-lab-marker');
    const probe = operation(2, 'probe', 'anonymous');
    const executor = new ScriptedExecutor(async (op, call) => {
      if (call === 1) return observation(op, 'owner', 200, {});
      throw Object.assign(new Error('probe failed'), { code: 'transport_network_error' });
    });

    const completed = await new ExperimentRunner().run(baseInput(store, plan([mutation, probe]), executor, {
      verifyMutation: async () => ({ applied: true, evidenceId: 'verification-applied' }),
      verifyCleanup: async () => false
    }));

    expect(executor.calls.map((call) => call.operationId)).toEqual([
      'github.rest.put-lab-marker',
      'github.rest.get-repository',
      'github.rest.delete-lab-marker'
    ]);
    expect(completed.manifest.result).toBe('dirty');
    expect(completed.cleanupStatus).toBe('failed');
  });

  it('stops before protected follow-up when the policy fingerprint changes and never promotes an anomaly', async () => {
    const store = new LabStore(await mkdtemp(join(tmpdir(), 'aegishub-runner-')));
    const operations = [
      operation(1, 'baseline', 'owner'),
      operation(2, 'probe', 'anonymous'),
      operation(3, 'repeat', 'anonymous'),
      operation(4, 'verify', 'owner')
    ];
    let current = 'd'.repeat(64);
    const executor = new ScriptedExecutor((op, call) => {
      if (call === 2) current = 'f'.repeat(64);
      return observation(op, op.actor, op.actor === 'owner' ? 200 : 200, { private: true }, { protectedData: op.actor !== 'owner' });
    });

    const completed = await new ExperimentRunner().run(baseInput(store, plan(operations), executor, {
      policyFingerprint: () => current
    }));

    expect(executor.calls).toHaveLength(2);
    expect(completed.manifest.result).toBe('policy_blocked');
    expect(completed.candidate).toBeUndefined();
  });
});
