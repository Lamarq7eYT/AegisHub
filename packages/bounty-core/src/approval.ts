import { createHash, randomBytes } from 'node:crypto';

import type { Actor, Budget, JsonValue } from './contracts.js';
import { stableJson } from './stable-json.js';

export interface PlannedExperimentOperation {
  readonly ordinal: number;
  readonly phase: 'setup' | 'baseline' | 'probe' | 'verify' | 'repeat' | 'cleanup';
  readonly stepId: string;
  readonly actor: Actor;
  readonly operationId: string;
  readonly parameters: Record<string, JsonValue>;
  readonly expectedEffect: string;
  readonly cleanupOperationId: string | null;
}

export interface ExperimentPlan {
  readonly schemaVersion: 1;
  readonly planId: string;
  readonly experimentId: string;
  readonly experimentVersion: number;
  readonly budgets: Budget;
  readonly operations: readonly PlannedExperimentOperation[];
}

export interface ApprovalFingerprintInput {
  readonly plan: ExperimentPlan;
  readonly ownerId: number;
  readonly researcherId: number;
  readonly manifestSha256: string;
  readonly policyFingerprint: string;
  readonly catalogFingerprint: string;
}

export interface ApprovalGrant {
  readonly fingerprint: string;
  readonly nonce: string;
  readonly expiresAt: string;
}

const consumedGrants = new WeakSet<object>();
const fingerprintPattern = /^[a-f0-9]{64}$/;
const MAX_GRANT_LIFETIME_MS = 5 * 60 * 1000;

export function createApprovalFingerprint(input: ApprovalFingerprintInput): string {
  const exactInput: JsonValue = {
    plan: input.plan as unknown as JsonValue,
    ownerId: input.ownerId,
    researcherId: input.researcherId,
    manifestSha256: input.manifestSha256,
    policyFingerprint: input.policyFingerprint,
    catalogFingerprint: input.catalogFingerprint
  };

  return createHash('sha256').update(stableJson(exactInput)).digest('hex');
}

export function createApprovalGrant(
  fingerprint: string,
  now: Date = new Date()
): ApprovalGrant {
  if (!fingerprintPattern.test(fingerprint)) {
    throw new Error('invalid_approval_fingerprint');
  }
  if (!Number.isFinite(now.getTime())) {
    throw new Error('invalid_approval_time');
  }

  return Object.freeze({
    fingerprint,
    nonce: randomBytes(32).toString('hex'),
    expiresAt: new Date(now.getTime() + MAX_GRANT_LIFETIME_MS).toISOString()
  });
}

export function consumeApprovalGrant(
  grant: ApprovalGrant,
  expectedFingerprint: string,
  now: Date = new Date()
): boolean {
  if (!fingerprintPattern.test(expectedFingerprint) || grant.fingerprint !== expectedFingerprint) {
    return false;
  }
  if (!Number.isFinite(now.getTime()) || now.getTime() >= Date.parse(grant.expiresAt)) {
    return false;
  }
  if (consumedGrants.has(grant)) {
    return false;
  }

  consumedGrants.add(grant);
  return true;
}
