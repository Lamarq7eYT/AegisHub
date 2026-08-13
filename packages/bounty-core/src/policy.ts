import { policySnapshotSchema, type PolicySnapshot, type PolicyStatus } from './contracts.js';
import { sha256StableJson } from './stable-json.js';

export type PolicyState = 'current' | 'fresh-unverified' | 'stale' | 'review-required';

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
  readonly schemaVersion: 1;
  readonly allowedTargetHosts: readonly string[];
  readonly forbiddenOperationFamilies: readonly PolicyOperationClassification[];
}

const fixedPolicyEnforcement: Readonly<PolicyEnforcement> = Object.freeze({
  schemaVersion: 1,
  allowedTargetHosts: Object.freeze(['api.github.com'] as const),
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

export const FIXED_POLICY_ENFORCEMENT_SHA256 = policyEnforcementFingerprint(fixedPolicyEnforcement);

const expectedPolicySources = Object.freeze([
  Object.freeze({ id: 'rules', url: 'https://bounty.github.com/rules.html' }),
  Object.freeze({ id: 'scope', url: 'https://bounty.github.com/scope.html' }),
  Object.freeze({ id: 'targets', url: 'https://bounty.github.com/targets.html' }),
  Object.freeze({ id: 'ineligible', url: 'https://bounty.github.com/ineligible.html' }),
  Object.freeze({ id: 'rewards', url: 'https://bounty.github.com/rewards.html' })
] as const);

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
  | 'incomplete_policy_source_results';

export class PolicyStatusError extends Error {
  constructor(readonly code: PolicyStatusRejectionReason) {
    super(code);
    this.name = 'PolicyStatusError';
  }
}

export class PolicyFingerprintError extends Error {
  constructor(readonly code: 'invalid_policy_snapshot' | 'invalid_policy_enforcement') {
    super(code);
    this.name = 'PolicyFingerprintError';
  }
}

export class PolicyGateInputError extends Error {
  constructor(readonly code: 'invalid_policy_gate_input' | 'unknown_operation_classification') {
    super(code);
    this.name = 'PolicyGateInputError';
  }
}

export function computePolicyStatus(input: {
  snapshot: PolicySnapshot;
  retrievals: readonly PolicySourceResult[];
  now: Date;
}): PolicyStatus {
  const snapshot = validateSnapshot(input.snapshot);
  assertValidDate(input.now, 'invalid_policy_snapshot');

  if (snapshot.enforcementSha256 !== FIXED_POLICY_ENFORCEMENT_SHA256) {
    throw new PolicyStatusError('enforcement_hash_mismatch');
  }

  const retrievals = validateRetrievals(input.retrievals, snapshot);
  const sourceStatuses = retrievals.map((retrieval) => ({
    sourceId: retrieval.sourceId,
    state: retrieval.state,
    checkedAt: retrieval.checkedAt.toISOString(),
    ...(retrieval.state === 'match' || retrieval.state === 'changed'
      ? { observedSha256: retrieval.observedSha256 }
      : {}),
    ...(retrieval.state === 'malformed' ? { malformedReason: retrieval.reason } : {})
  }));

  const sourceById = new Map(snapshot.sources.map((source) => [source.id, source]));
  const requiresReview = retrievals.some((retrieval) => {
    if (retrieval.state === 'changed' || retrieval.state === 'malformed') {
      return true;
    }
    return retrieval.state === 'match' && retrieval.observedSha256 !== sourceById.get(retrieval.sourceId)?.contentSha256;
  });

  const unavailable = retrievals.some((retrieval) => retrieval.state === 'unavailable');
  const reviewAgeMs = input.now.getTime() - new Date(snapshot.reviewedAt).getTime();
  if (reviewAgeMs < 0) {
    throw new PolicyStatusError('invalid_policy_snapshot');
  }
  const state: PolicyState = requiresReview
    ? 'review-required'
    : unavailable
      ? reviewAgeMs <= 30 * 24 * 60 * 60 * 1000
        ? 'fresh-unverified'
        : 'stale'
      : 'current';

  return {
    schemaVersion: 1,
    policyVersion: snapshot.policyVersion,
    state,
    checkedAt: input.now.toISOString(),
    sourceStatuses
  };
}

export function evaluatePolicyGate(input: PolicyGateInput): PolicyGateDecision {
  const parsed = parsePolicyGateInput(input);

  if (parsed.targets.some((target) => !fixedPolicyEnforcement.allowedTargetHosts.includes(target))) {
    return { allowed: false, reason: 'target_not_github_or_lab' };
  }
  if (
    parsed.operationFamilies.some((operationFamily) =>
      fixedPolicyEnforcement.forbiddenOperationFamilies.includes(operationFamily)
    )
  ) {
    return { allowed: false, reason: 'permanently_forbidden_operation' };
  }
  if (parsed.status.state === 'fresh-unverified') {
    return parsed.mutationCount > 0
      ? { allowed: false, reason: 'mutation_requires_current_policy' }
      : { allowed: true, warnings: ['fresh_unverified_policy'] as const };
  }
  if (parsed.status.state !== 'current') {
    return { allowed: false, reason: 'policy_not_current' };
  }

  return { allowed: true };
}

export function parsePolicyGateInput(input: unknown): PolicyGateInput {
  if (
    !isRecord(input) ||
    !hasExactKeys(input, ['status', 'mutationCount', 'targets', 'operationFamilies']) ||
    !isRecord(input.status) ||
    !hasExactKeys(input.status, ['state', 'checkedAt', 'sourceResults'])
  ) {
    throw new PolicyGateInputError('invalid_policy_gate_input');
  }
  const { status, mutationCount, targets, operationFamilies } = input;
  if (
    !isPolicyState(status.state) ||
    !isValidDate(status.checkedAt) ||
    !Array.isArray(status.sourceResults) ||
    !Number.isSafeInteger(mutationCount) ||
    mutationCount < 0 ||
    !isNonEmptyStringArray(targets) ||
    !Array.isArray(operationFamilies)
  ) {
    throw new PolicyGateInputError('invalid_policy_gate_input');
  }

  const parsedOperationFamilies = operationFamilies.map((operationFamily) => {
    if (!isPolicyOperationClassification(operationFamily)) {
      throw new PolicyGateInputError('unknown_operation_classification');
    }
    return operationFamily;
  });

  return {
    status: {
      state: status.state,
      checkedAt: status.checkedAt,
      sourceResults: validateGateSourceResults(status.sourceResults)
    },
    mutationCount,
    targets,
    operationFamilies: parsedOperationFamilies
  };
}

export function policyFingerprint(snapshot: PolicySnapshot): string {
  return policyFingerprintForEnforcement(snapshot, fixedPolicyEnforcement);
}

export function policyFingerprintForEnforcement(
  snapshot: PolicySnapshot,
  enforcement: PolicyEnforcement
): string {
  const parsedSnapshot = policySnapshotSchema.safeParse(snapshot);
  if (!parsedSnapshot.success || !hasExactPolicySources(parsedSnapshot.data)) {
    throw new PolicyFingerprintError('invalid_policy_snapshot');
  }
  if (!isPolicyEnforcement(enforcement)) {
    throw new PolicyFingerprintError('invalid_policy_enforcement');
  }
  return sha256StableJson({
    snapshot: parsedSnapshot.data,
    enforcement: policyEnforcementPayload(enforcement)
  });
}

function validateSnapshot(snapshot: PolicySnapshot): PolicySnapshot {
  const parsedSnapshot = policySnapshotSchema.safeParse(snapshot);
  if (!parsedSnapshot.success || !hasExactPolicySources(parsedSnapshot.data)) {
    throw new PolicyStatusError('invalid_policy_snapshot');
  }
  return parsedSnapshot.data;
}

function validateRetrievals(
  retrievals: readonly PolicySourceResult[],
  snapshot: PolicySnapshot
): readonly PolicySourceResult[] {
  if (retrievals.length !== expectedPolicySources.length) {
    throw new PolicyStatusError('incomplete_policy_source_results');
  }
  const expectedSources = new Map(snapshot.sources.map((source) => [source.id, source]));
  const seen = new Set<string>();
  for (const retrieval of retrievals) {
    if (!isPolicySourceResult(retrieval) || !expectedSources.has(retrieval.sourceId) || seen.has(retrieval.sourceId)) {
      throw new PolicyStatusError('incomplete_policy_source_results');
    }
    seen.add(retrieval.sourceId);
  }
  return retrievals;
}

function validateGateSourceResults(sourceResults: unknown[]): readonly PolicySourceResult[] {
  if (!sourceResults.every(isPolicySourceResult)) {
    throw new PolicyGateInputError('invalid_policy_gate_input');
  }
  return sourceResults;
}

function hasExactPolicySources(snapshot: PolicySnapshot): boolean {
  if (snapshot.sources.length !== expectedPolicySources.length) {
    return false;
  }
  const sourcesById = new Map(snapshot.sources.map((source) => [source.id, source]));
  if (sourcesById.size !== expectedPolicySources.length) {
    return false;
  }
  return expectedPolicySources.every(({ id, url }) => sourcesById.get(id)?.url === url);
}

function isPolicySourceResult(value: unknown): value is PolicySourceResult {
  if (!isRecord(value) || typeof value.sourceId !== 'string' || value.sourceId.length === 0 || !isValidDate(value.checkedAt)) {
    return false;
  }
  if (value.state === 'match' || value.state === 'changed') {
    return (
      hasExactKeys(value, ['sourceId', 'state', 'checkedAt', 'observedSha256']) &&
      isSha256(value.observedSha256)
    );
  }
  if (value.state === 'unavailable') {
    return hasExactKeys(value, ['sourceId', 'state', 'checkedAt']);
  }
  return (
    value.state === 'malformed' &&
    hasExactKeys(value, ['sourceId', 'state', 'checkedAt', 'reason']) &&
    (value.reason === 'missing-main' || value.reason === 'empty-normalized-content' || value.reason === 'invalid-normalized-content')
  );
}

function isPolicyEnforcement(value: unknown): value is PolicyEnforcement {
  return (
    isRecord(value) &&
    hasExactKeys(value, ['schemaVersion', 'allowedTargetHosts', 'forbiddenOperationFamilies']) &&
    value.schemaVersion === 1 &&
    isNonEmptyStringArray(value.allowedTargetHosts) &&
    isPlainArray(value.forbiddenOperationFamilies) &&
    value.forbiddenOperationFamilies.length > 0 &&
    value.forbiddenOperationFamilies.every(isForbiddenOperationClassification)
  );
}

function policyEnforcementFingerprint(enforcement: PolicyEnforcement): string {
  return sha256StableJson(policyEnforcementPayload(enforcement));
}

function policyEnforcementPayload(enforcement: PolicyEnforcement): {
  schemaVersion: number;
  allowedTargetHosts: string[];
  forbiddenOperationFamilies: string[];
} {
  return {
    schemaVersion: enforcement.schemaVersion,
    allowedTargetHosts: [...enforcement.allowedTargetHosts],
    forbiddenOperationFamilies: [...enforcement.forbiddenOperationFamilies]
  };
}

function isForbiddenOperationClassification(value: unknown): value is PolicyOperationClassification {
  return typeof value === 'string' && value !== 'repository-read-boundary' && value !== 'repository-mutation-boundary' && isPolicyOperationClassification(value);
}

function isPolicyOperationClassification(value: unknown): value is PolicyOperationClassification {
  return typeof value === 'string' && policyOperationClassifications.has(value);
}

const policyOperationClassifications = new Set<PolicyOperationClassification>([
  'repository-read-boundary',
  'repository-mutation-boundary',
  ...fixedPolicyEnforcement.forbiddenOperationFamilies
]);

function isPolicyState(value: unknown): value is PolicyState {
  return value === 'current' || value === 'fresh-unverified' || value === 'stale' || value === 'review-required';
}

function isNonEmptyStringArray(value: unknown): value is string[] {
  return (
    isPlainArray(value) &&
    value.length > 0 &&
    value.every((entry) => typeof entry === 'string' && entry.length > 0)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length > 0
  ) {
    return false;
  }
  return Object.values(Object.getOwnPropertyDescriptors(value)).every(
    (descriptor) => descriptor.enumerable === true && 'value' in descriptor
  );
}

function isPlainArray(value: unknown): value is unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    return false;
  }
  const ownNames = Object.getOwnPropertyNames(value);
  if (ownNames.length !== value.length + 1 || ownNames.at(-1) !== 'length') {
    return false;
  }
  return value.every((_, index) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    return descriptor?.enumerable === true && 'value' in descriptor;
  });
}

function hasExactKeys(value: Record<string, unknown>, expectedKeys: readonly string[]): boolean {
  const actualKeys = Object.keys(value).sort();
  const sortedExpectedKeys = [...expectedKeys].sort();
  return (
    actualKeys.length === sortedExpectedKeys.length &&
    actualKeys.every((key, index) => key === sortedExpectedKeys[index])
  );
}

function isValidDate(value: unknown): value is Date {
  return value instanceof Date && Number.isFinite(value.getTime());
}

function assertValidDate(value: unknown, code: PolicyStatusRejectionReason): asserts value is Date {
  if (!isValidDate(value)) {
    throw new PolicyStatusError(code);
  }
}

function isSha256(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/i.test(value);
}
