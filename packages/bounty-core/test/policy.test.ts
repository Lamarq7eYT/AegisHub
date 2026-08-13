import { describe, expect, it } from 'vitest';
import {
  computePolicyStatus,
  evaluatePolicyGate,
  FIXED_POLICY_ENFORCEMENT_SHA256,
  parsePolicyGateInput,
  policyFingerprint,
  policyFingerprintForEnforcement,
  PolicyGateInputError,
  type PolicyGateInput,
  PolicyStatusError,
  type PolicyOperationClassification,
  type PolicySourceResult
} from '../src/policy.js';
import { policySnapshotSchema, type PolicySnapshot } from '../src/contracts.js';

const now = new Date('2026-08-13T12:00:00.000Z');
const reviewedAt = '2026-07-14T12:00:00.000Z';

const sourceUrls = [
  'https://bounty.github.com/rules.html',
  'https://bounty.github.com/scope.html',
  'https://bounty.github.com/targets.html',
  'https://bounty.github.com/ineligible.html',
  'https://bounty.github.com/rewards.html'
] as const;

function sha256(seed: string): string {
  return seed.repeat(64).slice(0, 64);
}

function snapshot(overrides: Partial<PolicySnapshot> = {}): PolicySnapshot {
  return {
    schemaVersion: 1,
    policyVersion: 'github-bounty-2026-08-13.1',
    enforcementSha256: FIXED_POLICY_ENFORCEMENT_SHA256,
    sources: sourceUrls.map((url, index) => ({
      id: ['rules', 'scope', 'targets', 'ineligible', 'rewards'][index]!,
      url,
      retrievedAt: reviewedAt,
      contentSha256: sha256(String(index + 1))
    })),
    rulesOfEngagement: ['Only use reviewed, low-volume GitHub API operations.'],
    inScopeTargets: ['api.github.com'],
    ineligibleCategories: ['Availability and resource-exhaustion testing.'],
    severityReferences: ['GitHub Bug Bounty rewards.'],
    reviewedAt,
    ...overrides
  };
}

function matchingRetrievals(policy: PolicySnapshot): PolicySourceResult[] {
  return policy.sources.map((source) => ({
    sourceId: source.id,
    state: 'match',
    checkedAt: now,
    observedSha256: source.contentSha256
  }));
}

function gateInput(overrides: Partial<PolicyGateInput> = {}): PolicyGateInput {
  return {
    status: { state: 'current', checkedAt: now, sourceResults: [] },
    mutationCount: 0,
    targets: ['api.github.com'],
    operationFamilies: ['repository-read-boundary'],
    ...overrides
  };
}

function expectStatusRejection(
  run: () => unknown,
  code: 'invalid_policy_snapshot' | 'enforcement_hash_mismatch' | 'incomplete_policy_source_results'
): void {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(PolicyStatusError);
    expect((error as PolicyStatusError).code).toBe(code);
    return;
  }

  throw new Error(`Expected PolicyStatusError with code ${code}`);
}

function expectGateInputRejection(run: () => unknown, code: PolicyGateInputError['code']): void {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(PolicyGateInputError);
    expect((error as PolicyGateInputError).code).toBe(code);
    return;
  }

  throw new Error(`Expected PolicyGateInputError with code ${code}`);
}

describe('computePolicyStatus', () => {
  it.each([
    {
      name: 'marks all five matching reviewed sources current regardless of review age',
      policy: snapshot({ reviewedAt: '2020-01-01T00:00:00.000Z' }),
      retrievals: (policy: PolicySnapshot) => matchingRetrievals(policy),
      expected: 'current'
    },
    {
      name: 'requires review when any normalized source hash differs',
      policy: snapshot(),
      retrievals: (policy: PolicySnapshot) => [
        ...matchingRetrievals(policy).slice(0, 4),
        {
          sourceId: 'rewards',
          state: 'changed' as const,
          checkedAt: now,
          observedSha256: sha256('f')
        }
      ],
      expected: 'review-required'
    },
    {
      name: 'requires review when a source body is malformed instead of treating it as unavailable',
      policy: snapshot(),
      retrievals: (policy: PolicySnapshot) => [
        ...matchingRetrievals(policy).slice(0, 4),
        {
          sourceId: 'rewards',
          state: 'malformed' as const,
          checkedAt: now,
          reason: 'missing-main' as const
        }
      ],
      expected: 'review-required'
    },
    {
      name: 'allows only fresh-unverified status at exactly the 30-day review boundary',
      policy: snapshot(),
      retrievals: (policy: PolicySnapshot) =>
        policy.sources.map((source) => ({
          sourceId: source.id,
          state: 'unavailable' as const,
          checkedAt: now
        })),
      expected: 'fresh-unverified'
    },
    {
      name: 'marks unavailable sources stale after the 30-day review boundary',
      policy: snapshot({ reviewedAt: '2026-07-14T11:59:59.999Z' }),
      retrievals: (policy: PolicySnapshot) =>
        policy.sources.map((source) => ({
          sourceId: source.id,
          state: 'unavailable' as const,
          checkedAt: now
        })),
      expected: 'stale'
    }
  ])('$name', ({ policy, retrievals, expected }) => {
    expect(
      computePolicyStatus({ snapshot: policy, retrievals: retrievals(policy), now }).state
    ).toBe(expected);
  });

  it('rejects a malformed snapshot before assigning a freshness state', () => {
    expect(
      policySnapshotSchema.safeParse({ ...snapshot(), enforcementSha256: undefined }).success
    ).toBe(false);
    expectStatusRejection(
      () =>
        computePolicyStatus({
          snapshot: { ...snapshot(), sources: [] } as PolicySnapshot,
          retrievals: [],
          now
        }),
      'invalid_policy_snapshot'
    );
  });

  it('rejects an invalid source inside a snapshot before assigning a freshness state', () => {
    const invalidSourceSnapshot = {
      ...snapshot(),
      sources: [{ ...snapshot().sources[0]!, contentSha256: 'not-a-sha256' }]
    } as PolicySnapshot;

    expect(policySnapshotSchema.safeParse(invalidSourceSnapshot).success).toBe(false);
    expectStatusRejection(
      () =>
        computePolicyStatus({
          snapshot: invalidSourceSnapshot,
          retrievals: [],
          now
        }),
      'invalid_policy_snapshot'
    );
  });

  it('rejects an enforcement pin mismatch before assigning a freshness state', () => {
    expectStatusRejection(
      () =>
        computePolicyStatus({
          snapshot: snapshot({ enforcementSha256: sha256('f') }),
          retrievals: matchingRetrievals(snapshot()),
          now
        }),
      'enforcement_hash_mismatch'
    );
  });

  it('fails closed when fewer than all five source results are available', () => {
    expectStatusRejection(
      () =>
        computePolicyStatus({
          snapshot: snapshot(),
          retrievals: [{ sourceId: 'rules', state: 'unavailable', checkedAt: now }],
          now
        }),
      'incomplete_policy_source_results'
    );
  });

  it.each([
    {
      name: 'marks mixed matching and unavailable sources fresh-unverified at 30 days',
      policy: snapshot(),
      expected: 'fresh-unverified'
    },
    {
      name: 'marks mixed matching and unavailable sources stale after 30 days',
      policy: snapshot({ reviewedAt: '2026-07-14T11:59:59.999Z' }),
      expected: 'stale'
    }
  ])('$name', ({ policy, expected }) => {
    const retrievals = matchingRetrievals(policy).map((result, index) =>
      index < 2
        ? result
        : { sourceId: result.sourceId, state: 'unavailable' as const, checkedAt: now }
    );

    expect(computePolicyStatus({ snapshot: policy, retrievals, now }).state).toBe(expected);
  });

  it.each([
    {
      name: 'missing expected source in the reviewed snapshot',
      snapshot: snapshot({ sources: snapshot().sources.slice(0, 4) }),
      retrievals: (policy: PolicySnapshot) => matchingRetrievals(policy),
      code: 'invalid_policy_snapshot' as const
    },
    {
      name: 'duplicate source IDs in the reviewed snapshot',
      snapshot: snapshot({
        sources: [...snapshot().sources.slice(0, 4), { ...snapshot().sources[0]! }]
      }),
      retrievals: (policy: PolicySnapshot) => matchingRetrievals(policy),
      code: 'invalid_policy_snapshot' as const
    },
    {
      name: 'substituted source ID in the reviewed snapshot',
      snapshot: snapshot({
        sources: snapshot().sources.map((source, index) =>
          index === 4 ? { ...source, id: 'substituted-source' } : source
        )
      }),
      retrievals: (policy: PolicySnapshot) => matchingRetrievals(policy),
      code: 'invalid_policy_snapshot' as const
    },
    {
      name: 'substituted source URL in the reviewed snapshot',
      snapshot: snapshot({
        sources: snapshot().sources.map((source, index) =>
          index === 4 ? { ...source, url: 'https://bounty.github.com/substituted.html' } : source
        )
      }),
      retrievals: (policy: PolicySnapshot) => matchingRetrievals(policy),
      code: 'invalid_policy_snapshot' as const
    },
    {
      name: 'duplicate source results',
      snapshot: snapshot(),
      retrievals: (policy: PolicySnapshot) => [
        ...matchingRetrievals(policy).slice(0, 4),
        { ...matchingRetrievals(policy)[0]! }
      ],
      code: 'incomplete_policy_source_results' as const
    },
    {
      name: 'unknown source result',
      snapshot: snapshot(),
      retrievals: (policy: PolicySnapshot) => [
        ...matchingRetrievals(policy).slice(0, 4),
        {
          sourceId: 'unknown-source',
          state: 'match' as const,
          checkedAt: now,
          observedSha256: sha256('f')
        }
      ],
      code: 'incomplete_policy_source_results' as const
    }
  ])('rejects $name before assigning a freshness state', ({ snapshot: policy, retrievals, code }) => {
    expectStatusRejection(
      () => computePolicyStatus({ snapshot: policy, retrievals: retrievals(policy), now }),
      code
    );
  });
});

describe('evaluatePolicyGate', () => {
  it('permits read-only and mutating plans that are within a current reviewed policy', () => {
    expect(evaluatePolicyGate(gateInput())).toEqual({ allowed: true });
    expect(evaluatePolicyGate(gateInput({ mutationCount: 1 }))).toEqual({ allowed: true });
  });

  it('permits only read-only plans while fresh-unverified and emits a warning code', () => {
    expect(
      evaluatePolicyGate(
        gateInput({ status: { state: 'fresh-unverified', checkedAt: now, sourceResults: [] } })
      )
    ).toEqual({ allowed: true, warnings: ['fresh_unverified_policy'] });

    expect(
      evaluatePolicyGate({
        status: { state: 'fresh-unverified', checkedAt: now, sourceResults: [] },
        mutationCount: 1,
        targets: ['api.github.com'],
        operationFamilies: ['repository-read-boundary']
      })
    ).toEqual({
      allowed: false,
      reason: 'mutation_requires_current_policy'
    });
  });

  it.each(['stale', 'review-required'] as const)('blocks every active plan while %s', (state) => {
    expect(evaluatePolicyGate(gateInput({ status: { state, checkedAt: now, sourceResults: [] } }))).toEqual({
      allowed: false,
      reason: 'policy_not_current'
    });
  });

  it.each([
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
  ] satisfies readonly PolicyOperationClassification[])('rejects permanently forbidden %s operations', (operationFamily) => {
    expect(evaluatePolicyGate(gateInput({ operationFamilies: [operationFamily] }))).toEqual({
      allowed: false,
      reason: 'permanently_forbidden_operation'
    });
  });

  it('rejects non-GitHub and non-lab targets even while current', () => {
    expect(evaluatePolicyGate(gateInput({ targets: ['api.example.test'] }))).toEqual({
      allowed: false,
      reason: 'target_not_github_or_lab'
    });
    expect(evaluatePolicyGate(gateInput({ targets: ['github.com'] }))).toEqual({
      allowed: false,
      reason: 'target_not_github_or_lab'
    });
  });

  it('fails closed when parsing unknown operation classifications', () => {
    expectGateInputRejection(
      () =>
        parsePolicyGateInput({
          ...gateInput(),
          operationFamilies: ['unrecognized-operation-family']
        }),
      'unknown_operation_classification'
    );
  });

  it('fails closed when gate input has extra keys or a nonstandard prototype', () => {
    expectGateInputRejection(
      () => parsePolicyGateInput({ ...gateInput(), unexpected: true }),
      'invalid_policy_gate_input'
    );
    expectGateInputRejection(
      () => parsePolicyGateInput(Object.assign(Object.create({}), gateInput())),
      'invalid_policy_gate_input'
    );
  });
});

describe('policyFingerprint', () => {
  it('changes when a source hash, enforcement pin, or policy version changes', () => {
    const reviewed = snapshot();
    const sourceChanged = snapshot({
      sources: reviewed.sources.map((source, index) =>
        index === 0 ? { ...source, contentSha256: sha256('f') } : source
      )
    });
    const enforcementChanged = snapshot({ enforcementSha256: sha256('f') });
    const versionChanged = snapshot({ policyVersion: 'github-bounty-2026-08-13.2' });

    expect(policyFingerprint(reviewed)).not.toBe(policyFingerprint(sourceChanged));
    expect(policyFingerprint(reviewed)).not.toBe(policyFingerprint(enforcementChanged));
    expect(policyFingerprint(reviewed)).not.toBe(policyFingerprint(versionChanged));
  });

  it('changes immediately when fixed code-owned enforcement changes before pin re-review', () => {
    const reviewed = snapshot();
    const baseEnforcement = {
      schemaVersion: 1 as const,
      allowedTargetHosts: ['api.github.com'] as const,
      forbiddenOperationFamilies: ['credential-attack'] as const
    };
    const revisedEnforcement = {
      ...baseEnforcement,
      forbiddenOperationFamilies: ['credential-attack', 'shell-execution'] as const
    };

    expect(policyFingerprintForEnforcement(reviewed, baseEnforcement)).not.toBe(
      policyFingerprintForEnforcement(reviewed, revisedEnforcement)
    );
  });
});
