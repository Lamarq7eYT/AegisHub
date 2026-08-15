import { describe, expect, it } from 'vitest';

import {
  consumeApprovalGrant,
  createApprovalFingerprint,
  createApprovalGrant,
  type ApprovalFingerprintInput,
  type ExperimentPlan
} from '../src/approval.js';

const now = new Date('2026-08-13T12:00:00.000Z');

function makePlan(overrides: Partial<ExperimentPlan> = {}): ExperimentPlan {
  return {
    schemaVersion: 1,
    planId: '95f38cca-42e2-4b7d-82e6-f13f4549b2f3',
    experimentId: 'repo.private.contents-read-boundary.v1',
    experimentVersion: 1,
    budgets: {
      concurrency: 1,
      requestsPerSecond: 1,
      burst: 2,
      maxRequests: 12,
      maxMutations: 0,
      timeoutMs: 20_000,
      maxReadRetries: 2,
      maxMutationRetries: 0
    },
    operations: [
      {
        ordinal: 1,
        phase: 'baseline',
        stepId: 'owner-marker-baseline',
        actor: 'owner',
        operationId: 'github.rest.contents.get-lab-marker.v1',
        parameters: { owner: 'owner-fixture', repo: 'lab-fixture' },
        expectedEffect: 'owner_reads_marker',
        cleanupOperationId: null
      }
    ],
    ...overrides
  };
}

function makeInput(overrides: Partial<ApprovalFingerprintInput> = {}): ApprovalFingerprintInput {
  return {
    plan: makePlan(),
    ownerId: 1001,
    researcherId: 2002,
    manifestSha256: 'a'.repeat(64),
    policyFingerprint: 'b'.repeat(64),
    catalogFingerprint: 'c'.repeat(64),
    ...overrides
  };
}

describe('createApprovalFingerprint', () => {
  it('hashes the exact plan and approval context deterministically', () => {
    const input = makeInput();

    expect(createApprovalFingerprint(input)).toMatch(/^[a-f0-9]{64}$/);
    expect(createApprovalFingerprint(input)).toBe(createApprovalFingerprint(input));
  });

  it.each([
    ['operation', { plan: makePlan({ operations: [{ ...makePlan().operations[0]!, actor: 'researcher' }] }) }],
    ['parameter', { plan: makePlan({ operations: [{ ...makePlan().operations[0]!, parameters: { owner: 'other-fixture', repo: 'lab-fixture' } }] }) }],
    ['cleanup', { plan: makePlan({ operations: [{ ...makePlan().operations[0]!, cleanupOperationId: 'github.rest.contents.delete-lab-marker.v1' }] }) }],
    ['budget', { plan: makePlan({ budgets: { ...makePlan().budgets, maxRequests: 11 } }) }],
    ['owner identity', { ownerId: 1002 }],
    ['researcher identity', { researcherId: 2003 }],
    ['manifest', { manifestSha256: 'd'.repeat(64) }],
    ['policy', { policyFingerprint: 'e'.repeat(64) }],
    ['catalog', { catalogFingerprint: 'f'.repeat(64) }]
  ] as const)('changes when the %s changes', (_label, override) => {
    expect(createApprovalFingerprint(makeInput())).not.toBe(
      createApprovalFingerprint(makeInput(override))
    );
  });
});

describe('one-run ApprovalGrant', () => {
  it('contains the full fingerprint and expires within five minutes', () => {
    const fingerprint = createApprovalFingerprint(makeInput());
    const grant = createApprovalGrant(fingerprint, now);

    expect(grant.fingerprint).toBe(fingerprint);
    expect(grant.nonce).toMatch(/^[a-f0-9]{64}$/);
    expect(new Date(grant.expiresAt).getTime() - now.getTime()).toBeLessThanOrEqual(5 * 60 * 1000);
    expect(new Date(grant.expiresAt).getTime()).toBeGreaterThan(now.getTime());
  });

  it('can be consumed once only for the exact fingerprint', () => {
    const fingerprint = createApprovalFingerprint(makeInput());
    const grant = createApprovalGrant(fingerprint, now);

    expect(consumeApprovalGrant(grant, 'f'.repeat(64), now)).toBe(false);
    expect(consumeApprovalGrant(grant, fingerprint, now)).toBe(true);
    expect(consumeApprovalGrant(grant, fingerprint, now)).toBe(false);
  });

  it('rejects an expired grant without consuming a valid future grant', () => {
    const fingerprint = createApprovalFingerprint(makeInput());
    const grant = createApprovalGrant(fingerprint, now);

    expect(consumeApprovalGrant(grant, fingerprint, new Date(now.getTime() + 5 * 60 * 1000 + 1))).toBe(false);
    expect(consumeApprovalGrant(grant, fingerprint, now)).toBe(true);
  });
});
