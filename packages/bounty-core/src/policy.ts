import type { PolicySnapshot, PolicyStatus } from './contracts.js';

export type PolicyState = 'current' | 'fresh-unverified' | 'stale' | 'review-required';

export const FIXED_POLICY_ENFORCEMENT_SHA256 = 'e'.repeat(64);

export type PolicyOperationClassification =
  | 'repository-read-boundary'
  | 'repository-mutation-boundary'
  | 'credential-attack'
  | 'social-engineering'
  | 'enumeration-campaign'
  | 'high-volume-scan'
  | 'scraping'
  | 'fuzzing'
  | 'brute-force'
  | 'availability-test'
  | 'resource-exhaustion'
  | 'third-party-pii-collection'
  | 'third-party-secret-collection'
  | 'persistence-without-verified-cleanup'
  | 'raw-socket-access'
  | 'arbitrary-redirect'
  | 'arbitrary-http-host'
  | 'arbitrary-graphql'
  | 'shell-execution'
  | 'third-party-repository-content';

export interface PolicyEnforcement {
  version: number;
  forbiddenOperationFamilies: readonly PolicyOperationClassification[];
}

const fixedPolicyEnforcement: Readonly<PolicyEnforcement> = Object.freeze({
  version: 1,
  forbiddenOperationFamilies: Object.freeze([
    'credential-attack',
    'social-engineering',
    'enumeration-campaign',
    'high-volume-scan',
    'scraping',
    'fuzzing',
    'brute-force',
    'availability-test',
    'resource-exhaustion',
    'third-party-pii-collection',
    'third-party-secret-collection',
    'persistence-without-verified-cleanup',
    'raw-socket-access',
    'arbitrary-redirect',
    'arbitrary-http-host',
    'arbitrary-graphql',
    'shell-execution',
    'third-party-repository-content'
  ] as const)
});

export type PolicySourceResult =
  | {
      sourceId: string;
      state: 'match' | 'changed';
      checkedAt: Date;
      observedSha256: string;
    }
  | {
      sourceId: string;
      state: 'unavailable';
      checkedAt: Date;
    }
  | {
      sourceId: string;
      state: 'malformed';
      checkedAt: Date;
      reason: 'missing-main' | 'empty-normalized-content' | 'invalid-normalized-content';
    };

export interface PolicyGateInput {
  status: {
    state: PolicyState;
    checkedAt: Date;
    sourceResults: readonly PolicySourceResult[];
  };
  mutationCount: number;
  targets: readonly string[];
  operationFamilies: readonly PolicyOperationClassification[];
}

export type PolicyGateDecision =
  | { allowed: true; warnings?: readonly ['fresh_unverified_policy'] }
  | {
      allowed: false;
      reason:
        | 'mutation_requires_current_policy'
        | 'policy_not_current'
        | 'permanently_forbidden_operation'
        | 'target_not_github_or_lab';
    };

export type PolicyStatusRejectionReason =
  | 'invalid_policy_snapshot'
  | 'enforcement_hash_mismatch'
  | 'incomplete_policy_source_results'
  | 'unimplemented_policy_evaluation';

export class PolicyStatusError extends Error {
  constructor(readonly code: PolicyStatusRejectionReason) {
    super(code);
    this.name = 'PolicyStatusError';
  }
}

export class PolicyFingerprintError extends Error {
  constructor(readonly code: 'unimplemented_policy_fingerprinting') {
    super(code);
    this.name = 'PolicyFingerprintError';
  }
}

export function computePolicyStatus(_input: {
  snapshot: PolicySnapshot;
  retrievals: readonly PolicySourceResult[];
  now: Date;
}): PolicyStatus {
  throw new PolicyStatusError('unimplemented_policy_evaluation');
}

export function evaluatePolicyGate(_input: PolicyGateInput): PolicyGateDecision {
  throw new Error('Policy gate evaluation is not implemented');
}

export function parsePolicyGateInput(_input: unknown): PolicyGateInput {
  throw new Error('Policy gate input parsing is not implemented');
}

export function policyFingerprint(snapshot: PolicySnapshot): string {
  return policyFingerprintForEnforcement(snapshot, fixedPolicyEnforcement);
}

export function policyFingerprintForEnforcement(
  _snapshot: PolicySnapshot,
  _enforcement: PolicyEnforcement
): string {
  throw new PolicyFingerprintError('unimplemented_policy_fingerprinting');
}
