import { describe, expect, it } from 'vitest';
import { labManifestSchema } from '../src/contracts.js';

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
});
