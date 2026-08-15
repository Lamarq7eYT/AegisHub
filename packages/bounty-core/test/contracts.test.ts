import { describe, expect, it } from 'vitest';
import {
  actorSchema,
  analystInputSchema,
  analystOutputSchema,
  candidateSchema,
  evidenceIndexSchema,
  experimentSchema,
  githubIdentitySchema,
  jsonValueSchema,
  labManifestSchema,
  labRepositorySchema,
  observationSchema,
  policySourceStatusSchema,
  policySnapshotSchema,
  repositoryMarkerSchema
} from '../src/contracts.js';
import { sha256StableJson, stableJson } from '../src/stable-json.js';

const sha256 = 'a'.repeat(64);
const timestamp = '2026-08-13T12:00:00.000Z';
const labId = '95f38cca-42e2-4b7d-82e6-f13f4549b2f3';
const runId = '570b117d-d6e3-4406-aa05-ca1ea8e89d5f';

const validRepository = {
  id: 3003,
  nodeId: 'R_fixture',
  ownerId: 1001,
  owner: 'owner-fixture',
  name: 'lab-repository',
  fullName: 'owner-fixture/lab-repository',
  markerSha256: sha256
};

const validLab = {
  schemaVersion: 1,
  labId,
  githubHost: 'github.com',
  owner: { id: 1001, nodeId: 'U_owner', login: 'owner-fixture' },
  researcher: { id: 2002, nodeId: 'U_researcher', login: 'researcher-fixture' },
  repositories: [validRepository],
  approvedOperationFamilies: ['repository-read-boundary'],
  budgets: {
    concurrency: 1,
    requestsPerSecond: 1,
    burst: 2,
    maxRequests: 100,
    maxMutations: 10,
    timeoutMs: 20_000,
    maxReadRetries: 2,
    maxMutationRetries: 0
  },
  retention: { maxResponseBytes: 262_144, keepRuns: 20 },
  createdAt: timestamp,
  verifiedAt: timestamp
};

const validStep = {
  id: 'owner-read',
  phase: 'baseline' as const,
  operationId: 'github.rest.repos.get',
  actor: 'owner' as const,
  repositoryId: 3003,
  parameters: { owner: 'owner-fixture', repository: 'lab-repository' }
};

const validExperiment = {
  schemaVersion: 1,
  id: 'repo.private.contents-read-boundary.v1',
  version: 1,
  title: 'Private contents boundary',
  researchQuestion: 'Can an untrusted actor read lab-owned private contents?',
  scopeTarget: 'github.com',
  ineligibleCategoryChecks: ['repository content is lab-owned'],
  requiredLabCapabilities: ['private-repository'],
  budgets: validLab.budgets,
  steps: [validStep],
  normalizationProfile: 'github-rest-v1',
  expectation: {
    kind: 'access-boundary' as const,
    ownerSuccessStatuses: [200],
    untrustedDeniedStatuses: [404],
    protectedFields: ['content'],
    requireOwnerRepeat: true as const,
    minimumConsistentUntrustedAttempts: 2
  },
  expectedSafeOutcome: 'Untrusted actors cannot read protected content.',
  anomalyCondition: 'An untrusted actor receives protected content.'
};

const validObservation = {
  schemaVersion: 1,
  observationId: '1ab0f284-93f9-4efb-b2cc-a08cf0d1f446',
  runId,
  experimentId: validExperiment.id,
  experimentVersion: 1,
  operationId: validStep.operationId,
  actor: 'owner' as const,
  repositoryId: 3003,
  observedAt: timestamp,
  durationMs: 12,
  method: 'GET' as const,
  endpointTemplate: '/repos/{owner}/{repo}',
  parameters: validStep.parameters,
  status: 200,
  headers: { 'content-type': 'application/json' },
  normalizedBody: { id: 3003, private: true },
  bodySha256: sha256,
  repeatGroup: 'owner-repository',
  protectedData: false,
  outOfLab: false,
  policyVersion: 'github-bounty-2026-08',
  catalogVersion: '1'
};

const validEvidenceIndex = {
  schemaVersion: 1,
  runId,
  generatedAt: timestamp,
  entries: [
    {
      evidenceId: 'observation-owner-read',
      kind: 'observation' as const,
      path: 'observations.ndjson',
      sha256
    }
  ]
};

const validPolicySnapshot = {
  schemaVersion: 1,
  policyVersion: 'github-bounty-2026-08',
  enforcementSha256: sha256,
  sources: [
    {
      id: 'rules',
      url: 'https://bounty.github.com/rules.html',
      retrievedAt: timestamp,
      contentSha256: sha256
    }
  ],
  rulesOfEngagement: ['Use the official program rules.'],
  inScopeTargets: ['github.com'],
  ineligibleCategories: ['Availability impact'],
  severityReferences: [],
  reviewedAt: timestamp
};

const validCandidate = {
  schemaVersion: 1,
  candidateId: '94d452cd-93b6-4a93-993d-2d7fc4e1f758',
  runId,
  experimentId: validExperiment.id,
  crossedBoundary: 'private repository contents',
  reproductionCount: 2,
  independentlyVerified: true as const,
  knownIneligible: false as const,
  impact: { kind: 'confidentiality' as const, summary: 'Lab-owned contents exposed.' },
  cleanupStatus: 'complete' as const,
  evidenceIds: ['observation-owner-read'],
  reproductionSteps: ['Run the reviewed lab experiment.']
};

const validAnalystInput = {
  schemaVersion: 1,
  labId,
  runId,
  evidenceIds: ['observation-owner-read'],
  sanitizedObservations: [validObservation],
  priorSummaries: ['The owner baseline succeeded.'],
  policyExcerptIds: ['rules'],
  availableOperationIds: ['github.rest.repos.get']
};

const validAnalystOutput = {
  schemaVersion: 1,
  hypotheses: [{ hypothesis: 'The boundary behaves as expected.', evidenceIds: ['observation-owner-read'] }],
  benignExplanations: ['No protected content was returned to an untrusted actor.'],
  evidenceGaps: [],
  suggestedOperationIds: ['github.rest.repos.get'],
  suggestedActorArrangements: [['owner', 'researcher', 'anonymous']],
  confidenceRationale: {
    summary: 'The observation supports the expected boundary.',
    evidenceIds: ['observation-owner-read']
  }
};

describe('labManifestSchema', () => {
  it('rejects an unknown safety setting', () => {
    const result = labManifestSchema.safeParse({
      schemaVersion: 1,
      labId: '95f38cca-42e2-4b7d-82e6-f13f4549b2f3',
      githubHost: 'github.com',
      owner: { id: 1001, nodeId: 'U_owner', login: 'owner-fixture' },
      researcher: { id: 2002, nodeId: 'U_researcher', login: 'researcher-fixture' },
      repositories: [],
      approvedOperationFamilies: ['repository-read-boundary'],
      budgets: {
        concurrency: 1,
        requestsPerSecond: 1,
        burst: 2,
        maxRequests: 100,
        maxMutations: 10,
        timeoutMs: 20_000,
        maxReadRetries: 2,
        maxMutationRetries: 0
      },
      retention: { maxResponseBytes: 262_144, keepRuns: 20 },
      createdAt: '2026-08-13T12:00:00.000Z',
      verifiedAt: '2026-08-13T12:00:00.000Z',
      allowArbitraryHosts: true
    });

    expect(result.success).toBe(false);
  });

  it('rejects invalid actors, identities, hosts, and repository names', () => {
    expect(actorSchema.safeParse('owner').success).toBe(true);
    expect(actorSchema.safeParse('researcher').success).toBe(true);
    expect(actorSchema.safeParse('anonymous').success).toBe(true);
    expect(actorSchema.safeParse('administrator').success).toBe(false);
    expect(githubIdentitySchema.safeParse({ id: 0, nodeId: 'U', login: 'user' }).success).toBe(false);
    expect(
      githubIdentitySchema.safeParse({ id: 1.5, nodeId: 'U', login: 'user' }).success
    ).toBe(false);
    expect(
      githubIdentitySchema.safeParse({ id: Number.MAX_SAFE_INTEGER + 1, nodeId: 'U', login: 'user' })
        .success
    ).toBe(false);
    expect(githubIdentitySchema.safeParse({ id: 1, nodeId: '', login: 'user' }).success).toBe(false);
    expect(githubIdentitySchema.safeParse({ id: 1, nodeId: 'U', login: '' }).success).toBe(false);
    expect(labManifestSchema.safeParse({ ...validLab, githubHost: 'api.github.com' }).success).toBe(false);
    expect(
      labRepositorySchema.safeParse({
        ...validRepository,
        fullName: 'owner-fixture/lab-repository/extra'
      }).success
    ).toBe(false);
    expect(
      labRepositorySchema.safeParse({
        ...validRepository,
        fullName: 'different-owner/lab-repository'
      }).success
    ).toBe(false);
  });

  it('rejects unknown fields on persisted and analyst contracts', () => {
    expect(repositoryMarkerSchema.safeParse({
      schemaVersion: 1,
      labId,
      repositoryId: 3003,
      ownerId: 1001,
      controlNonce: 'control-nonce-1234',
      unsafe: true
    }).success).toBe(false);
    expect(policySnapshotSchema.safeParse({ ...validPolicySnapshot, unsafe: true }).success).toBe(false);
    expect(experimentSchema.safeParse({ ...validExperiment, unsafe: true }).success).toBe(false);
    expect(observationSchema.safeParse({ ...validObservation, unsafe: true }).success).toBe(false);
    expect(candidateSchema.safeParse({ ...validCandidate, unsafe: true }).success).toBe(false);
    expect(analystInputSchema.safeParse({ ...validAnalystInput, unsafe: true }).success).toBe(false);
    expect(analystOutputSchema.safeParse({ ...validAnalystOutput, unsafe: true }).success).toBe(false);
  });

  it('represents malformed policy source status distinctly from transport unavailability', () => {
    expect(
      policySourceStatusSchema.safeParse({
        sourceId: 'rules',
        state: 'malformed',
        checkedAt: timestamp,
        malformedReason: 'missing-main'
      }).success
    ).toBe(true);
    expect(
      policySourceStatusSchema.safeParse({
        sourceId: 'rules',
        state: 'malformed',
        checkedAt: timestamp
      }).success
    ).toBe(false);
    expect(
      policySourceStatusSchema.safeParse({
        sourceId: 'rules',
        state: 'unavailable',
        checkedAt: timestamp,
        malformedReason: 'missing-main'
      }).success
    ).toBe(false);
  });

  it('accepts only typed operation steps in experiment phases', () => {
    expect(experimentSchema.safeParse(validExperiment).success).toBe(true);
    expect(
      experimentSchema.safeParse({
        ...validExperiment,
        steps: [{ ...validStep, phase: 'execute' }]
      }).success
    ).toBe(false);
    expect(
      experimentSchema.safeParse({
        ...validExperiment,
        steps: [{ phase: 'probe', script: 'curl https://example.invalid' }]
      }).success
    ).toBe(false);
  });

  it('rejects non-JSON evidence values', () => {
    class EvidenceRecord {
      public readonly id = 'record';
    }
    const cyclic: { self?: unknown } = {};
    cyclic.self = cyclic;
    const sparse = [1];
    sparse.length = 3;
    const extended = [1];
    Object.defineProperty(extended, 'unsafe', { enumerable: true, value: () => undefined });

    for (const value of [
      undefined,
      () => undefined,
      Symbol('evidence'),
      Infinity,
      new EvidenceRecord(),
      cyclic,
      sparse,
      extended
    ]) {
      expect(jsonValueSchema.safeParse(value).success).toBe(false);
    }
    expect(jsonValueSchema.safeParse({ [Symbol('evidence')]: 'hidden' }).success).toBe(false);
  });

  it('rejects Array subclasses that can forge JSON serialization', () => {
    class ForgedArray extends Array<number> {
      public toJSON(): { forged: boolean } {
        return { forged: true };
      }
    }

    const forged = new ForgedArray();
    forged.push(1);

    expect(jsonValueSchema.safeParse(forged).success).toBe(false);
    expect(() => stableJson(forged as never)).toThrow('JSON-compatible');
  });

  it('round-trips complete persisted documents', () => {
    const lab = labManifestSchema.parse(validLab);
    const experiment = experimentSchema.parse(validExperiment);
    const observation = observationSchema.parse(validObservation);
    const evidenceIndex = evidenceIndexSchema.parse(validEvidenceIndex);

    expect(labManifestSchema.parse(JSON.parse(JSON.stringify(lab)))).toEqual(lab);
    expect(experimentSchema.parse(JSON.parse(JSON.stringify(experiment)))).toEqual(experiment);
    expect(observationSchema.parse(JSON.parse(JSON.stringify(observation)))).toEqual(observation);
    expect(evidenceIndexSchema.parse(JSON.parse(JSON.stringify(evidenceIndex)))).toEqual(evidenceIndex);
  });

  it('uses stable object ordering while preserving array ordering', () => {
    expect(sha256StableJson({ b: 2, a: { z: 1, y: 0 } })).toBe(
      sha256StableJson({ a: { y: 0, z: 1 }, b: 2 })
    );
    expect(sha256StableJson({ values: [1, 2] })).not.toBe(sha256StableJson({ values: [2, 1] }));
    expect(stableJson({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
    const protoKey = JSON.parse('{"__proto__":{"value":1}}');
    expect(stableJson(protoKey)).toBe('{"__proto__":{"value":1}}');
    expect(sha256StableJson(protoKey)).not.toBe(sha256StableJson({}));
    expect(() => stableJson(Infinity as never)).toThrow('JSON-compatible');
  });
});
