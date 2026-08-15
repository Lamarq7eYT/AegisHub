import { describe, expect, it } from 'vitest';

import { renderReport, renderReproduction } from '../src/evidence/report.js';
import { type VerifiedEvidenceBundle } from '../src/evidence/writer.js';

const timestamp = '2026-08-13T12:00:00.000Z';
const runId = '3e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12';

function bundle(result: 'expected' | 'inconclusive' | 'anomalous' = 'expected'): VerifiedEvidenceBundle {
  return {
    path: '/synthetic/aegishub-run',
    runId,
    manifest: {
      schemaVersion: 1,
      runId,
      labId: '95f38cca-42e2-4b7d-82e6-f13f4549b2f3',
      policyVersion: 'policy-v1',
      experimentId: 'repo.private.contents-read-boundary.v1',
      experimentVersion: 1,
      startedAt: timestamp,
      completedAt: timestamp,
      result,
      requestCount: 4,
      mutationCount: 0,
      cleanupStatus: 'not-required'
    },
    policy: {
      schemaVersion: 1,
      policyVersion: 'policy-v1',
      state: 'current',
      checkedAt: timestamp,
      sourceStatuses: [{ sourceId: 'roe', state: 'match', checkedAt: timestamp, observedSha256: 'a'.repeat(64) }]
    },
    experiment: {
      schemaVersion: 1,
      id: 'repo.private.contents-read-boundary.v1',
      version: 1,
      title: 'Private repository contents read boundary',
      researchQuestion: 'Can an untrusted actor read a marker?',
      scopeTarget: 'owner-fixture/lab-fixture',
      ineligibleCategoryChecks: ['no-third-party-target'],
      requiredLabCapabilities: ['private-repository'],
      budgets: { concurrency: 1, requestsPerSecond: 1, burst: 2, maxRequests: 8, maxMutations: 0, timeoutMs: 20_000, maxReadRetries: 2, maxMutationRetries: 0 },
      steps: [],
      normalizationProfile: 'repository-v1',
      expectation: { kind: 'access-boundary', ownerSuccessStatuses: [200], untrustedDeniedStatuses: [403, 404], protectedFields: ['marker'], requireOwnerRepeat: true, minimumConsistentUntrustedAttempts: 2 },
      expectedSafeOutcome: 'Only owner succeeds.',
      anomalyCondition: 'Untrusted actor reads protected data.'
    },
    plan: {
      schemaVersion: 1,
      planId: runId,
      experimentId: 'repo.private.contents-read-boundary.v1',
      experimentVersion: 1,
      budgets: { concurrency: 1, requestsPerSecond: 1, burst: 2, maxRequests: 8, maxMutations: 0, timeoutMs: 20_000, maxReadRetries: 2, maxMutationRetries: 0 },
      operations: [{ ordinal: 1, phase: 'baseline', stepId: 'owner-baseline', actor: 'owner', operationId: 'github.rest.repos.get.v1', parameters: { owner: 'owner-fixture', repo: 'lab-fixture' }, expectedEffect: 'read-only observation', cleanupOperationId: null }]
    },
    observations: [{
      schemaVersion: 1,
      observationId: '5e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12',
      runId,
      experimentId: 'repo.private.contents-read-boundary.v1',
      experimentVersion: 1,
      operationId: 'github.rest.repos.get.v1',
      actor: 'owner',
      repositoryId: 3003,
      observedAt: timestamp,
      durationMs: 2,
      method: 'GET',
      endpointTemplate: '/repos/{owner}/{repo}',
      parameters: { owner: 'owner-fixture', repo: 'lab-fixture' },
      status: 200,
      headers: { 'content-type': 'application/json' },
      normalizedBody: { repository: 'lab-fixture' },
      bodySha256: 'b'.repeat(64),
      repeatGroup: 'owner-repeat',
      protectedData: false,
      outOfLab: false,
      policyVersion: 'policy-v1',
      catalogVersion: '1.0.0'
    }],
    diff: {
      schemaVersion: 1,
      diffId: '4e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12',
      runId,
      experimentId: 'repo.private.contents-read-boundary.v1',
      comparedObservationIds: ['5e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12', '6e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12'],
      outcome: result,
      dimensions: ['authorization-boundary'],
      summary: 'Synthetic classification summary.',
      details: { sanitized: true }
    },
    ...(result === 'anomalous' ? { candidate: {
      schemaVersion: 1,
      candidateId: '7e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12',
      runId,
      experimentId: 'repo.private.contents-read-boundary.v1',
      crossedBoundary: 'access-boundary',
      reproductionCount: 2,
      independentlyVerified: true,
      knownIneligible: false,
      impact: { kind: 'confidentiality', summary: 'Synthetic lab-owned impact.' },
      cleanupStatus: 'complete',
      evidenceIds: ['5e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12'],
      reproductionSteps: ['Repeat the reviewed catalog operation.']
    } } : {})
  } as VerifiedEvidenceBundle;
}

describe('evidence reports', () => {
  it('renders all required report sections for a safe experiment result', () => {
    const report = renderReport(bundle());
    expect(report).toContain('## Summary');
    expect(report).toContain('## Affected GitHub Surface');
    expect(report).toContain('## Preconditions');
    expect(report).toContain('## Reproduction');
    expect(report).toContain('## Observed Result');
    expect(report).toContain('## Expected Result');
    expect(report).toContain('## Impact');
    expect(report).toContain('## Evidence Index');
    expect(report).toContain('## Cleanup Confirmation');
    expect(report).not.toMatch(/CVSS|bounty|confirmed vulnerability|automatic submission|ghp_|curl\s/i);
  });

  it('labels anomalies as candidates for human validation and never as confirmed vulnerabilities', () => {
    const report = renderReport(bundle('anomalous'));
    expect(report).toContain('Candidate for human validation');
    expect(report).not.toMatch(/confirmed vulnerability|severity:\s*critical|CVSS|submit automatically/i);
  });

  it('renders reproduction using catalog operation names and sanitized CLI only', () => {
    const reproduction = renderReproduction(bundle());
    expect(reproduction).toContain('github.rest.repos.get.v1');
    expect(reproduction).toContain('aegishub bounty');
    expect(reproduction).not.toMatch(/curl|Authorization:|Cookie:|https?:\/\/|\$\{|raw body|browser cookie/i);
  });
});
