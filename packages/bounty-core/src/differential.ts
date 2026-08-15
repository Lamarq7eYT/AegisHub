import { sha256StableJson } from './stable-json.js';
import type {
  Candidate,
  Diff,
  JsonObject,
  JsonValue,
  Observation,
  BoundaryExpectation,
  RunManifest
} from './contracts.js';

export type DifferentialObservation = Observation & {
  readonly repeatGroup: string;
  readonly protectedData: boolean;
  readonly outOfLab: boolean;
  readonly errorClass?: string;
};

export interface DifferentialInput {
  readonly observations: readonly DifferentialObservation[];
  readonly expectation: BoundaryExpectation;
  readonly policy: {
    readonly allowed: boolean;
    readonly reason?: string;
  };
  readonly cleanupStatus: 'not-required' | 'complete' | 'failed' | 'manual-resolution-required';
  readonly independentVerification: boolean;
  readonly impact: {
    readonly kind: 'confidentiality' | 'integrity';
    readonly summary: string;
    readonly labOwned: boolean;
  };
  readonly ineligibleClasses: readonly string[];
}

export interface DifferentialResult {
  readonly state: RunManifest['result'];
  readonly reason?: string;
  readonly diff?: Diff;
  readonly candidate?: Candidate;
}

const volatileKeys = new Set([
  'requestid',
  'request_id',
  'timestamp',
  'ratelimit',
  'rate_limit',
  'rateremaining',
  'rate_remaining',
  'self',
  'selflink',
  'actor_self_link'
]);

const signedQueryPattern = /([?&](?:sig|signature|x-amz-signature|expires|x-amz-expires)=)[^&#\s]+/gi;

function normalizeJson(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    return value.map(normalizeJson);
  }

  if (value !== null && typeof value === 'object') {
    const normalized: JsonObject = {};
    for (const [key, child] of Object.entries(value)) {
      if (volatileKeys.has(key.toLowerCase())) {
        continue;
      }
      normalized[key] = normalizeJson(child);
    }
    return normalized;
  }

  if (typeof value === 'string') {
    return value.replace(signedQueryPattern, '$1[volatile]');
  }

  return value;
}

export function normalizeObservation(
  observation: DifferentialObservation,
  profile = 'github-private-marker-v1'
): DifferentialObservation {
  if (profile !== 'github-private-marker-v1') {
    throw new Error('unsupported_normalization_profile');
  }

  return Object.freeze({
    ...observation,
    normalizedBody: normalizeJson(observation.normalizedBody)
  });
}

function deterministicUuid(seed: JsonValue): string {
  const digest = sha256StableJson(seed);
  const bytes = digest.slice(0, 32).split('');
  bytes[12] = '4';
  const versionNibble = bytes[16] ?? '0';
  bytes[16] = ['8', '9', 'a', 'b'][Number.parseInt(versionNibble, 16) % 4] ?? '8';
  return `${bytes.slice(0, 8).join('')}-${bytes.slice(8, 12).join('')}-${bytes
    .slice(12, 16)
    .join('')}-${bytes.slice(16, 20).join('')}-${bytes.slice(20).join('')}`;
}

function semanticKey(observation: DifferentialObservation): string {
  return JSON.stringify({
    status: observation.status,
    errorClass: observation.errorClass ?? null,
    normalizedBody: observation.normalizedBody
  });
}

function groupByActorAndRepeat(
  observations: readonly DifferentialObservation[]
): Map<string, DifferentialObservation[]> {
  const groups = new Map<string, DifferentialObservation[]>();
  for (const observation of observations) {
    const key = `${observation.actor}:${observation.repeatGroup}`;
    const current = groups.get(key) ?? [];
    current.push(observation);
    groups.set(key, current);
  }
  return groups;
}

function hasConsistentGroup(
  groups: ReadonlyMap<string, readonly DifferentialObservation[]>,
  predicate: (observation: DifferentialObservation) => boolean,
  minimum: number
): DifferentialObservation[] | undefined {
  for (const group of groups.values()) {
    const matching = group.filter(predicate);
    if (matching.length < minimum) {
      continue;
    }

    const first = matching[0];
    if (first === undefined) {
      continue;
    }
    const firstKey = semanticKey(first);
    if (matching.every((observation) => semanticKey(observation) === firstKey)) {
      return matching;
    }
  }

  return undefined;
}

function makeDiff(
  observations: readonly DifferentialObservation[],
  outcome: 'expected' | 'anomalous' | 'inconclusive',
  summary: string,
  dimensions: readonly string[]
): Diff {
  const comparedObservationIds = observations.map((observation) => observation.observationId);
  const seed: JsonValue = {
    outcome,
    comparedObservationIds,
    summary,
    dimensions: [...dimensions]
  };

  return {
    schemaVersion: 1,
    diffId: deterministicUuid(seed),
    runId: observations[0]?.runId ?? deterministicUuid({ kind: 'empty-run' }),
    experimentId: observations[0]?.experimentId ?? 'unknown',
    comparedObservationIds,
    outcome,
    dimensions: [...dimensions],
    summary,
    details: {
      normalizedObservationCount: observations.length,
      semanticComparison: sha256StableJson({
        observations: observations.map((observation) => ({
          actor: observation.actor,
          status: observation.status,
          body: observation.normalizedBody
        }))
      })
    }
  };
}

function isVerifiedIntegritySideEffect(observation: DifferentialObservation): boolean {
  if (observation.verifiedSideEffect === undefined || typeof observation.verifiedSideEffect !== 'object' || observation.verifiedSideEffect === null || Array.isArray(observation.verifiedSideEffect)) return false;
  return observation.verifiedSideEffect.applied === true;
}

function makeCandidate(
  observations: readonly DifferentialObservation[],
  expectation: BoundaryExpectation,
  impact: DifferentialInput['impact']
): Candidate {
  const firstObservation = observations[0];
  if (firstObservation === undefined) {
    throw new Error('candidate_requires_observation');
  }
  const evidenceIds = observations.map((observation) => observation.observationId);
  const seed: JsonValue = {
    evidenceIds,
    boundary: expectation.kind,
    impact: impact.summary
  };

  return {
    schemaVersion: 1,
    candidateId: deterministicUuid(seed),
    runId: firstObservation.runId,
    experimentId: firstObservation.experimentId,
    crossedBoundary: expectation.kind,
    reproductionCount: observations.length,
    independentlyVerified: true,
    knownIneligible: false,
    impact: {
      kind: impact.kind,
      summary: impact.summary
    },
    cleanupStatus: 'complete',
    evidenceIds,
    reproductionSteps: [
      'Repeat the same reviewed catalog operation as the untrusted actor.',
      'Compare the sanitized normalized response with the owner baseline.',
      'Verify the lab-owned impact independently as the owner.'
    ]
  };
}

export function classifyRun(input: DifferentialInput): DifferentialResult {
  const normalized = input.observations.map((observation) => normalizeObservation(observation));

  if (!input.policy.allowed) {
    return {
      state: 'policy_blocked',
      reason: input.policy.reason ?? 'policy_blocked'
    };
  }

  if (input.cleanupStatus === 'failed' || input.cleanupStatus === 'manual-resolution-required') {
    return {
      state: 'dirty',
      reason: 'cleanup_unverified'
    };
  }

  if (normalized.some((observation) => observation.outOfLab)) {
    return {
      state: 'inconclusive',
      reason: 'out_of_lab_resource',
      diff: makeDiff(normalized, 'inconclusive', 'An observation referenced a resource outside the verified lab.', [
        'resource-id'
      ])
    };
  }

  if (input.ineligibleClasses.length > 0) {
    return {
      state: 'inconclusive',
      reason: input.ineligibleClasses.includes('precondition_not_met') ? 'precondition_not_met' : 'known_ineligible_class',
      diff: makeDiff(normalized, 'inconclusive', 'A typed ineligible classification was present.', ['policy'])
    };
  }

  if (
    normalized.some(
      (observation) => (observation.errorClass !== undefined && !['access_denied', 'not_found'].includes(observation.errorClass)) || observation.status >= 500
    )
  ) {
    return {
      state: 'inconclusive',
      reason: 'transient_or_incomplete_observation',
      diff: makeDiff(normalized, 'inconclusive', 'At least one observation was transient or incomplete.', [
        'status',
        'error-class'
      ])
    };
  }

  const ownerObservations = normalized.filter((observation) => observation.actor === 'owner');
  const untrustedObservations = normalized.filter((observation) => observation.actor !== 'owner');
  const groups = groupByActorAndRepeat(normalized);
  const ownerRepeat = hasConsistentGroup(
    groups,
    (observation) => observation.actor === 'owner' && input.expectation.ownerSuccessStatuses.includes(observation.status),
    input.expectation.requireOwnerRepeat ? 2 : 1
  );

  if (ownerObservations.length === 0 || ownerRepeat === undefined) {
    return {
      state: 'inconclusive',
      reason: 'owner_repeat_missing',
      diff: makeDiff(normalized, 'inconclusive', 'The owner baseline could not be independently repeated.', [
        'owner-repeat'
      ])
    };
  }

  const protectedRepeat = hasConsistentGroup(
    groups,
    (observation) => observation.actor !== 'owner' && observation.protectedData,
    input.expectation.minimumConsistentUntrustedAttempts
  );

  if (
    protectedRepeat !== undefined &&
    input.independentVerification &&
    input.impact.labOwned &&
    (input.cleanupStatus === 'complete' || input.cleanupStatus === 'not-required')
  ) {
    const candidate = makeCandidate(protectedRepeat, input.expectation, input.impact);
    return {
      state: 'anomalous',
      diff: makeDiff(
        normalized,
        'anomalous',
        'A consistent untrusted actor observation crossed the declared access boundary.',
        ['authorization-boundary', 'protected-data', 'repeat-consistency']
      ),
      candidate
    };
  }

  const verifiedIntegrity = normalized.find((observation) => observation.actor !== 'owner' && isVerifiedIntegritySideEffect(observation));
  if (
    verifiedIntegrity !== undefined &&
    ownerRepeat !== undefined &&
    input.independentVerification &&
    input.impact.kind === 'integrity' &&
    input.impact.labOwned &&
    (input.cleanupStatus === 'complete' || input.cleanupStatus === 'not-required')
  ) {
    const ownerConfirmation = ownerRepeat[ownerRepeat.length - 1];
    if (ownerConfirmation !== undefined) {
      const candidate = makeCandidate([verifiedIntegrity, ownerConfirmation], input.expectation, input.impact);
      return {
        state: 'anomalous',
        diff: makeDiff(
          normalized,
          'anomalous',
          'A verified untrusted mutation crossed the declared integrity boundary and was confirmed by the owner.',
          ['authorization-boundary', 'integrity-boundary', 'repeat-consistency']
        ),
        candidate
      };
    }
  }

  if (untrustedObservations.length === 0) {
    return {
      state: 'inconclusive',
      reason: 'untrusted-observations-missing',
      diff: makeDiff(normalized, 'inconclusive', 'No untrusted actor observations were available.', ['coverage'])
    };
  }

  if (untrustedObservations.some((observation) => observation.protectedData)) {
    return {
      state: 'inconclusive',
      reason: 'protected-data-repeat-incomplete',
      diff: makeDiff(normalized, 'inconclusive', 'Protected data was observed without complete candidate proof.', [
        'protected-data',
        'repeat-consistency'
      ])
    };
  }

  const safeDenied = untrustedObservations.every((observation) =>
    input.expectation.untrustedDeniedStatuses.includes(observation.status)
  );
  if (safeDenied) {
    return {
      state: 'expected',
      diff: makeDiff(
        normalized,
        'expected',
        'Owner access succeeded and untrusted actors were denied without protected data.',
        ['authorization-boundary', 'protected-data']
      )
    };
  }

  return {
    state: 'inconclusive',
    reason: 'boundary-evidence-incomplete',
    diff: makeDiff(normalized, 'inconclusive', 'The observed actor relationship did not establish the declared boundary.', [
      'authorization-boundary'
    ])
  };
}
