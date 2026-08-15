import { mkdtemp, readFile, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';
import type {
  BoundaryExpectation,
  Candidate,
  Diff,
  Experiment,
  ExperimentPlan,
  Observation,
  PolicyStatus,
  RunManifest
} from '@aegishub/bounty-core';

import type { CompletedRun } from '../src/experiments/runner.js';
import {
  AtomicEvidenceWriter,
  EvidenceWriterError,
  type EvidenceContext
} from '../src/evidence/writer.js';

const timestamp = '2026-08-13T12:00:00.000Z';
const runId = '3e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12';
const labId = '95f38cca-42e2-4b7d-82e6-f13f4549b2f3';
const repositoryId = 3003;
const expectation: BoundaryExpectation = {
  kind: 'access-boundary',
  ownerSuccessStatuses: [200],
  untrustedDeniedStatuses: [403, 404],
  protectedFields: ['marker'],
  requireOwnerRepeat: true,
  minimumConsistentUntrustedAttempts: 2
};

function policy(overrides: Partial<PolicyStatus> = {}): PolicyStatus {
  return {
    schemaVersion: 1,
    policyVersion: 'policy-v1',
    state: 'current',
    checkedAt: timestamp,
    sourceStatuses: [{
      sourceId: 'github-bounty-roe',
      state: 'match',
      checkedAt: timestamp,
      observedSha256: 'a'.repeat(64)
    }],
    ...overrides
  };
}

function experiment(): Experiment {
  const read = (id: string, phase: 'baseline' | 'probe' | 'repeat', actor: 'owner' | 'anonymous', stepId: string): Experiment['steps'][number] => ({
    id: stepId,
    phase,
    actor,
    operationId: id.includes('marker') ? 'github.rest.contents.get-lab-marker.v1' : 'github.rest.repos.get.v1',
    repositoryId,
    parameters: { owner: 'owner-fixture', repo: 'lab-fixture' }
  });
  return {
    schemaVersion: 1,
    id: 'repo.private.contents-read-boundary.v1',
    version: 1,
    title: 'Private repository contents read boundary',
    researchQuestion: 'Can an untrusted actor read the verified lab marker from a private repository?',
    scopeTarget: 'owner-fixture/lab-fixture',
    ineligibleCategoryChecks: ['no-third-party-target'],
    requiredLabCapabilities: ['private-repository'],
    budgets: {
      concurrency: 1,
      requestsPerSecond: 1,
      burst: 2,
      maxRequests: 8,
      maxMutations: 0,
      timeoutMs: 20_000,
      maxReadRetries: 2,
      maxMutationRetries: 0
    },
    steps: [
      read('owner-repository-baseline', 'baseline', 'owner', 'owner-baseline'),
      read('anonymous-marker-probe-1', 'probe', 'anonymous', 'anonymous-probe-1-marker'),
      read('anonymous-marker-probe-2', 'repeat', 'anonymous', 'anonymous-probe-2-marker'),
      read('owner-final-repeat', 'repeat', 'owner', 'owner-final-repeat')
    ],
    normalizationProfile: 'repository-v1',
    expectation,
    expectedSafeOutcome: 'Only the owner can read private marker content.',
    anomalyCondition: 'Anonymous repeat observations contain protected marker content.'
  };
}

function plan(): ExperimentPlan & EvidenceContext['plan'] {
  return {
    schemaVersion: 1,
    planId: runId,
    experimentId: 'repo.private.contents-read-boundary.v1',
    experimentVersion: 1,
    budgets: experiment().budgets,
    operations: [
      { ordinal: 1, phase: 'baseline', stepId: 'owner-baseline', actor: 'owner', operationId: 'github.rest.repos.get.v1', parameters: { owner: 'owner-fixture', repo: 'lab-fixture' }, expectedEffect: 'read-only observation', cleanupOperationId: null },
      { ordinal: 2, phase: 'probe', stepId: 'anonymous-probe-1-marker', actor: 'anonymous', operationId: 'github.rest.contents.get-lab-marker.v1', parameters: { owner: 'owner-fixture', repo: 'lab-fixture' }, expectedEffect: 'read-only observation', cleanupOperationId: null },
      { ordinal: 3, phase: 'repeat', stepId: 'anonymous-probe-2-marker', actor: 'anonymous', operationId: 'github.rest.contents.get-lab-marker.v1', parameters: { owner: 'owner-fixture', repo: 'lab-fixture' }, expectedEffect: 'read-only observation', cleanupOperationId: null },
      { ordinal: 4, phase: 'repeat', stepId: 'owner-final-repeat', actor: 'owner', operationId: 'github.rest.repos.get.v1', parameters: { owner: 'owner-fixture', repo: 'lab-fixture' }, expectedEffect: 'read-only observation', cleanupOperationId: null }
    ]
  };
}

function observation(id: string, actor: 'owner' | 'anonymous', status: number, body: Record<string, unknown>, overrides: Partial<Observation> = {}): Observation {
  return {
    schemaVersion: 1,
    observationId: id,
    runId,
    experimentId: 'repo.private.contents-read-boundary.v1',
    experimentVersion: 1,
    operationId: actor === 'anonymous' ? 'github.rest.contents.get-lab-marker.v1' : 'github.rest.repos.get.v1',
    actor,
    repositoryId,
    observedAt: timestamp,
    durationMs: 2,
    method: 'GET',
    endpointTemplate: '/repos/{owner}/{repo}',
    parameters: { owner: 'owner-fixture', repo: 'lab-fixture' },
    status,
    headers: { 'content-type': 'application/json' },
    normalizedBody: body as import('@aegishub/bounty-core').JsonValue,
    bodySha256: 'b'.repeat(64),
    repeatGroup: actor === 'owner' ? 'owner-repeat' : 'anonymous-marker-repeat',
    protectedData: false,
    outOfLab: false,
    policyVersion: 'policy-v1',
    catalogVersion: '1.0.0',
    ...overrides
  };
}

function diff(outcome: Diff['outcome'] = 'expected'): Diff {
  return {
    schemaVersion: 1,
    diffId: '4e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12',
    runId,
    experimentId: 'repo.private.contents-read-boundary.v1',
    comparedObservationIds: [
      '5e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12',
      '6e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12'
    ],
    outcome,
    dimensions: ['authorization-boundary'],
    summary: outcome === 'anomalous' ? 'Candidate requires human validation.' : 'Expected denied boundary.',
    details: { normalizedObservationCount: 4 }
  };
}

function manifest(result: RunManifest['result'] = 'expected'): RunManifest {
  return {
    schemaVersion: 1,
    runId,
    labId,
    policyVersion: 'policy-v1',
    experimentId: 'repo.private.contents-read-boundary.v1',
    experimentVersion: 1,
    startedAt: timestamp,
    completedAt: timestamp,
    result,
    requestCount: 4,
    mutationCount: 0,
    cleanupStatus: 'not-required'
  };
}

function candidate(): Candidate {
  return {
    schemaVersion: 1,
    candidateId: '7e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12',
    runId,
    experimentId: 'repo.private.contents-read-boundary.v1',
    crossedBoundary: 'access-boundary',
    reproductionCount: 2,
    independentlyVerified: true,
    knownIneligible: false,
    impact: { kind: 'confidentiality', summary: 'Synthetic marker content was exposed within the owned lab.' },
    cleanupStatus: 'complete',
    evidenceIds: ['5e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12', '6e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12'],
    reproductionSteps: ['Repeat the reviewed catalog operation as the untrusted actor.']
  };
}

function run(result: RunManifest['result'] = 'expected'): CompletedRun {
  const anomalous = result === 'anomalous';
  return {
    manifest: manifest(result),
    observations: [
      observation('5e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12', 'owner', 200, { repository: 'lab-fixture' }),
      observation('6e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12', 'anonymous', anomalous ? 200 : 404, anomalous ? { marker: 'synthetic-protected' } : { message: 'not found' }, { protectedData: anomalous }),
      observation('8e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12', 'anonymous', anomalous ? 200 : 404, anomalous ? { marker: 'synthetic-protected' } : { message: 'not found' }, { protectedData: anomalous }),
      observation('9e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12', 'owner', 200, { repository: 'lab-fixture' })
    ],
    diff: diff(anomalous ? 'anomalous' : 'expected'),
    ...(anomalous ? { candidate: candidate() } : {}),
    cleanupStatus: 'not-required',
    recovery: { status: 'none' }
  };
}

function context(workspaceRoot: string, overrides: Partial<EvidenceContext> = {}): EvidenceContext {
  return {
    workspaceRoot,
    lab: {
      labId,
      ownerId: 1001,
      researcherId: 2002,
      repository: { id: repositoryId, nodeId: 'R_lab_fixture', owner: 'owner-fixture', name: 'lab-fixture', fullName: 'owner-fixture/lab-fixture' },
      markerSha256: 'c'.repeat(64)
    },
    policy: policy(),
    policyExcerptIds: ['roe-access-boundary-v1'],
    experiment: experiment(),
    plan: Object.assign(plan(), {
      planFingerprint: 'd'.repeat(64),
      manifestSha256: 'e'.repeat(64),
      policyFingerprint: 'f'.repeat(64),
      catalogFingerprint: 'a'.repeat(64)
    }),
    ...overrides
  };
}

describe('AtomicEvidenceWriter', () => {
  it('writes the canonical sanitized layout and sorted checksums atomically', async () => {
    const workspace = await mkdtemp(join(tmpdir(), 'aegishub-evidence-'));
    const writer = new AtomicEvidenceWriter(context(workspace));

    const result = await writer.write(run());
    const files = await Promise.all(result.files.map(async (file) => file.relativePath));
    expect(files).toEqual([
      'checksums.txt', 'diff.json', 'experiment.json', 'manifest.json', 'observations.ndjson',
      'plan.json', 'policy.json', 'reproduce.md', 'report.md'
    ].sort());
    expect(result.path).toBe(join(workspace, '.aegishub', 'runs', runId));
    expect(await readFile(join(result.path, 'checksums.txt'), 'utf8')).toMatch(/diff\.json/);
    await expect(writer.inspect(runId)).resolves.toMatchObject({ runId, verified: true });
  });

  it('writes candidate.json only for anomalous runs and includes no seeded token', async () => {
    const workspace = await mkdtemp(join(tmpdir(), 'aegishub-evidence-'));
    const secret = 'ghp_SYNTHETIC_TOKEN_MUST_NOT_APPEAR';
    const writer = new AtomicEvidenceWriter(context(workspace));
    const result = await writer.write(run('anomalous'));
    const candidateText = await readFile(join(result.path, 'candidate.json'), 'utf8');
    expect(candidateText).not.toContain(secret);
    expect(result.files.map((file) => file.relativePath)).toContain('candidate.json');
  });

  it('refuses overwrite, symlink traversal, and unsafe output path', async () => {
    const workspace = await mkdtemp(join(tmpdir(), 'aegishub-evidence-'));
    const writer = new AtomicEvidenceWriter(context(workspace));
    await writer.write(run());
    await expect(writer.write(run())).rejects.toMatchObject({ code: 'evidence_target_exists' });

    const outside = await mkdtemp(join(tmpdir(), 'aegishub-evidence-outside-'));
    const symlinkedRuns = join(workspace, '.aegishub', 'runs');
    const freshWorkspace = await mkdtemp(join(tmpdir(), 'aegishub-evidence-link-'));
    await symlink(outside, join(freshWorkspace, '.aegishub'));
    await expect(new AtomicEvidenceWriter(context(freshWorkspace)).write(run())).rejects.toMatchObject({ code: 'evidence_symlink_rejected' });
    expect(symlinkedRuns).not.toBe(outside);
  });

  it('does not publish a bundle when a rendered value contains a suspected secret', async () => {
    const workspace = await mkdtemp(join(tmpdir(), 'aegishub-evidence-'));
    const unsafePolicy = policy({ policyVersion: 'contains ghp_SYNTHETIC_TOKEN_MUST_NOT_APPEAR' });
    const writer = new AtomicEvidenceWriter(context(workspace, { policy: unsafePolicy }));

    await expect(writer.write(run())).rejects.toEqual(new EvidenceWriterError('evidence_secret_rejected'));
    await expect(writer.inspect(runId)).rejects.toMatchObject({ code: 'evidence_bundle_missing' });
  });

  it('exports a sanitized analysis pack without overwriting the selected directory', async () => {
    const workspace = await mkdtemp(join(tmpdir(), 'aegishub-evidence-'));
    const writer = new AtomicEvidenceWriter(context(workspace));
    await writer.write(run());
    const exportDirectory = join(workspace, 'exported-pack');

    const result = await writer.export(runId, exportDirectory);
    expect(result.path).toBe(exportDirectory);
    const pack = JSON.parse(await readFile(join(exportDirectory, 'analysis-pack.json'), 'utf8')) as Record<string, unknown>;
    expect(pack).toMatchObject({ labId, runId });
    await expect(writer.export(runId, exportDirectory)).rejects.toMatchObject({ code: 'evidence_export_exists' });
  });
});
