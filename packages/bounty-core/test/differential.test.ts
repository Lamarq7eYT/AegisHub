import { describe, expect, it } from 'vitest';

import {
  classifyRun,
  normalizeObservation,
  type DifferentialInput,
  type DifferentialObservation
} from '../src/differential.js';
import type { Actor, JsonValue } from '../src/contracts.js';

const runId = '95f38cca-42e2-4b7d-82e6-f13f4549b2f3';
const expectation = {
  kind: 'access-boundary' as const,
  ownerSuccessStatuses: [200],
  untrustedDeniedStatuses: [403, 404],
  protectedFields: ['marker.schemaVersion', 'marker.labId'],
  requireOwnerRepeat: true as const,
  minimumConsistentUntrustedAttempts: 2
};

function makeObservation(
  observationId: string,
  actor: Actor,
  status: number,
  body: JsonValue,
  repeatGroup: string,
  options: Partial<Pick<DifferentialObservation, 'protectedData' | 'outOfLab' | 'errorClass'>> = {}
): DifferentialObservation {
  const observation: DifferentialObservation = {
    schemaVersion: 1,
    observationId,
    runId,
    experimentId: 'repo.private.contents-read-boundary.v1',
    experimentVersion: 1,
    operationId: 'github.rest.contents.get-lab-marker.v1',
    actor,
    repositoryId: 3003,
    observedAt: '2026-08-13T12:00:00.000Z',
    durationMs: 10,
    method: 'GET',
    endpointTemplate: '/repos/{owner}/{repo}/contents/.aegishub-lab.json',
    parameters: { owner: 'owner-fixture', repo: 'lab-fixture' },
    status,
    headers: {},
    normalizedBody: body,
    bodySha256: 'a'.repeat(64),
    policyVersion: 'github-bounty-2026-08-13.1',
    catalogVersion: '1.1.0',
    repeatGroup,
    protectedData: options.protectedData ?? false,
    outOfLab: options.outOfLab ?? false
  };
  const errorClass = options.errorClass ?? (status >= 500 ? 'transient-server' : undefined);
  return errorClass === undefined ? observation : { ...observation, errorClass };
}

function baseInput(observations: readonly DifferentialObservation[]): DifferentialInput {
  return {
    observations,
    expectation,
    policy: { allowed: true },
    cleanupStatus: 'not-required',
    independentVerification: false,
    impact: {
      kind: 'confidentiality',
      summary: 'Synthetic lab-owned marker data was accessed',
      labOwned: true
    },
    ineligibleClasses: []
  };
}

describe('classifyRun', () => {
  it('classifies the known-safe owner/untrusted denial matrix as expected', () => {
    const result = classifyRun(
      baseInput([
        makeObservation('00000000-0000-4000-8000-000000000001', 'owner', 200, { marker: 'owner' }, 'owner-marker'),
        makeObservation('00000000-0000-4000-8000-000000000002', 'researcher', 404, {}, 'researcher-marker'),
        makeObservation('00000000-0000-4000-8000-000000000003', 'researcher', 404, {}, 'researcher-marker'),
        makeObservation('00000000-0000-4000-8000-000000000004', 'anonymous', 404, {}, 'anonymous-marker'),
        makeObservation('00000000-0000-4000-8000-000000000005', 'anonymous', 404, {}, 'anonymous-marker'),
        makeObservation('00000000-0000-4000-8000-000000000006', 'owner', 200, { marker: 'owner' }, 'owner-marker')
      ])
    );

    expect(result.state).toBe('expected');
    expect(result.candidate).toBeUndefined();
  });

  it('promotes two consistent protected researcher observations to an anomalous candidate', () => {
    const result = classifyRun({
      ...baseInput([
        makeObservation('00000000-0000-4000-8000-000000000011', 'owner', 200, { marker: 'owner' }, 'owner-marker'),
        makeObservation(
          '00000000-0000-4000-8000-000000000012',
          'researcher',
          200,
          { schemaVersion: 1, labId: runId },
          'researcher-marker',
          { protectedData: true }
        ),
        makeObservation(
          '00000000-0000-4000-8000-000000000013',
          'researcher',
          200,
          { schemaVersion: 1, labId: runId },
          'researcher-marker',
          { protectedData: true }
        ),
        makeObservation('00000000-0000-4000-8000-000000000014', 'owner', 200, { marker: 'owner' }, 'owner-marker')
      ]),
      independentVerification: true
    });

    expect(result.state).toBe('anomalous');
    expect(result.candidate).toMatchObject({
      reproductionCount: 2,
      independentlyVerified: true,
      knownIneligible: false,
      cleanupStatus: 'complete'
    });
  });

  it('prefers inconclusive when a transient researcher response prevents proof', () => {
    const result = classifyRun(
      baseInput([
        makeObservation('00000000-0000-4000-8000-000000000021', 'owner', 200, {}, 'owner-marker'),
        makeObservation(
          '00000000-0000-4000-8000-000000000022',
          'researcher',
          500,
          {},
          'researcher-marker',
          { errorClass: 'transient-server' }
        ),
        makeObservation('00000000-0000-4000-8000-000000000023', 'researcher', 404, {}, 'researcher-marker'),
        makeObservation('00000000-0000-4000-8000-000000000024', 'owner', 200, {}, 'owner-marker')
      ])
    );

    expect(result.state).toBe('inconclusive');
    expect(result.candidate).toBeUndefined();
  });

  it('returns policy_blocked before classifying observations', () => {
    const result = classifyRun({
      ...baseInput([]),
      policy: { allowed: false, reason: 'policy_changed_during_run' }
    });

    expect(result.state).toBe('policy_blocked');
    expect(result.reason).toBe('policy_changed_during_run');
  });

  it('returns dirty when cleanup is not verified', () => {
    const result = classifyRun({
      ...baseInput([
        makeObservation('00000000-0000-4000-8000-000000000031', 'owner', 200, {}, 'owner-marker')
      ]),
      cleanupStatus: 'failed'
    });

    expect(result.state).toBe('dirty');
    expect(result.reason).toBe('cleanup_unverified');
  });

  it('does not promote a cosmetic identity or status difference to a candidate', () => {
    const result = classifyRun(
      baseInput([
        makeObservation('00000000-0000-4000-8000-000000000036', 'owner', 200, { marker: 'owner' }, 'owner-marker'),
        makeObservation('00000000-0000-4000-8000-000000000037', 'researcher', 200, { login: 'researcher-fixture' }, 'researcher-marker'),
        makeObservation('00000000-0000-4000-8000-000000000038', 'researcher', 200, { login: 'researcher-fixture' }, 'researcher-marker'),
        makeObservation('00000000-0000-4000-8000-000000000039', 'owner', 200, { marker: 'owner' }, 'owner-marker')
      ])
    );

    expect(result.state).not.toBe('anomalous');
    expect(result.candidate).toBeUndefined();
  });

  it('requires repeated protected data before producing a candidate', () => {
    const result = classifyRun({
      ...baseInput([
        makeObservation('00000000-0000-4000-8000-000000000046', 'owner', 200, { marker: 'owner' }, 'owner-marker'),
        makeObservation('00000000-0000-4000-8000-000000000047', 'researcher', 200, { schemaVersion: 1, labId: runId }, 'researcher-marker', { protectedData: true }),
        makeObservation('00000000-0000-4000-8000-000000000048', 'owner', 200, { marker: 'owner' }, 'owner-marker')
      ]),
      independentVerification: true
    });

    expect(result.state).not.toBe('anomalous');
    expect(result.candidate).toBeUndefined();
  });

  it('does not promote differences limited to volatile response fields', () => {
    const result = classifyRun(
      baseInput([
        makeObservation('00000000-0000-4000-8000-000000000041', 'owner', 200, { marker: 'owner' }, 'owner-marker'),
        makeObservation(
          '00000000-0000-4000-8000-000000000042',
          'researcher',
          404,
          { requestId: 'request-a', timestamp: '2026-08-13T12:00:00.000Z', rateRemaining: 99, self: 'actor-a' },
          'researcher-marker'
        ),
        makeObservation(
          '00000000-0000-4000-8000-000000000043',
          'researcher',
          404,
          { requestId: 'request-b', timestamp: '2026-08-13T12:01:00.000Z', rateRemaining: 98, self: 'actor-b' },
          'researcher-marker'
        ),
        makeObservation('00000000-0000-4000-8000-000000000044', 'owner', 200, { marker: 'owner' }, 'owner-marker')
      ])
    );

    expect(result.state).toBe('expected');
  });

  it('stops safely when an observation is outside the pinned lab', () => {
    const result = classifyRun(
      baseInput([
        makeObservation(
          '00000000-0000-4000-8000-000000000051',
          'researcher',
          200,
          { repositoryId: 9999 },
          'researcher-marker',
          { outOfLab: true, protectedData: true }
        )
      ])
    );

    expect(result.state).toBe('inconclusive');
    expect(result.reason).toBe('out_of_lab_resource');
    expect(result.candidate).toBeUndefined();
  });
});

describe('normalizeObservation', () => {
  it('removes only the fixed volatile fields while preserving semantic content', () => {
    const normalized = normalizeObservation({
      schemaVersion: 1,
      observationId: '00000000-0000-4000-8000-000000000061',
      runId,
      experimentId: 'repo.private.contents-read-boundary.v1',
      experimentVersion: 1,
      operationId: 'github.rest.contents.get-lab-marker.v1',
      actor: 'researcher',
      repositoryId: 3003,
      observedAt: '2026-08-13T12:00:00.000Z',
      durationMs: 10,
      method: 'GET',
      endpointTemplate: '/repos/{owner}/{repo}/contents/.aegishub-lab.json',
      parameters: { owner: 'owner-fixture', repo: 'lab-fixture' },
      status: 404,
      headers: {},
      normalizedBody: {
        requestId: 'request-a',
        timestamp: '2026-08-13T12:00:00.000Z',
        rateRemaining: 99,
        self: 'https://github.example.test/users/researcher',
        marker: { schemaVersion: 1, labId: runId }
      },
      bodySha256: 'b'.repeat(64),
      policyVersion: 'github-bounty-2026-08-13.1',
      catalogVersion: '1.1.0',
      repeatGroup: 'researcher-marker',
      protectedData: false,
      outOfLab: false
    });

    expect(normalized.normalizedBody).toEqual({
      marker: { schemaVersion: 1, labId: runId }
    });
  });
});
