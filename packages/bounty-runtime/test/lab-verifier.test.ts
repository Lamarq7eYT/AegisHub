import { describe, expect, it } from 'vitest';
import { sha256StableJson, type LabManifest } from '@aegishub/bounty-core';

import { LabStore } from '../src/lab/store.js';
import {
  LabVerifier,
  type ConfigurationMutationJournal,
  type LabEnrollmentGateway,
  type ResolvedRepository,
  type RemoteMarker
} from '../src/lab/verifier.js';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const timestamp = '2026-08-13T12:00:00.000Z';
const marker: RemoteMarker = {
  schemaVersion: 1,
  labId: '95f38cca-42e2-4b7d-82e6-f13f4549b2f3',
  repositoryId: 3003,
  ownerId: 1001,
  controlNonce: 'fixture-control-nonce-1234567890'
};
const markerHash = sha256StableJson(marker);

const repository: ResolvedRepository = {
  id: 3003,
  nodeId: 'R_lab_fixture',
  ownerId: 1001,
  ownerLogin: 'owner-fixture',
  name: 'lab-fixture',
  fullName: 'owner-fixture/lab-fixture',
  private: true,
  ownerKind: 'user'
};

function manifest(overrides: Partial<LabManifest> = {}): LabManifest {
  return {
    schemaVersion: 1,
    labId: marker.labId,
    githubHost: 'github.com',
    owner: { id: 1001, nodeId: 'U_owner_fixture', login: 'owner-fixture' },
    researcher: { id: 2002, nodeId: 'U_researcher_fixture', login: 'researcher-fixture' },
    repositories: [{
      id: repository.id,
      nodeId: repository.nodeId,
      ownerId: repository.ownerId,
      owner: 'owner-fixture',
      name: repository.name,
      fullName: repository.fullName,
      markerSha256: markerHash
    }],
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
    verifiedAt: timestamp,
    ...overrides
  };
}

class FakeJournal implements ConfigurationMutationJournal {
  readonly events: string[] = [];
  async prepare(entry: { entryId: string }): Promise<void> { this.events.push(`prepare:${entry.entryId}`); }
  async markSent(entryId: string): Promise<void> { this.events.push(`sent:${entryId}`); }
  async markVerified(entryId: string): Promise<void> { this.events.push(`verified:${entryId}`); }
  async markRolledBack(entryId: string): Promise<void> { this.events.push(`rolled-back:${entryId}`); }
  async markDirty(entryId: string, reason: string): Promise<void> { this.events.push(`dirty:${entryId}:${reason}`); }
}

function makeGateway(options: {
  marker?: RemoteMarker | 'missing';
  repository?: ResolvedRepository;
  createMarker?: RemoteMarker;
  deleteFails?: boolean;
} = {}): LabEnrollmentGateway & { calls: string[] } {
  const calls: string[] = [];
  let currentMarker = options.marker ?? marker;
  return {
    calls,
    async resolveOwnedRepository() { calls.push('resolve'); return options.repository ?? repository; },
    async readMarker() { calls.push('read'); return currentMarker; },
    async createMarker(input) { calls.push('create'); currentMarker = options.createMarker ?? input.marker; return currentMarker; },
    async deleteMarker() {
      calls.push('delete');
      if (options.deleteFails) throw new Error('delete_fixture_failure');
      currentMarker = 'missing';
    }
  };
}

async function makeStore(saved = true): Promise<{ store: LabStore; workspace: string }> {
  const workspace = await mkdtemp(join(tmpdir(), 'aegishub-lab-verifier-'));
  const store = new LabStore(workspace);
  if (saved) await store.writeNew(manifest());
  return { store, workspace };
}

describe('LabVerifier.verify', () => {
  it('resolves current metadata first and verifies the immutable marker boundary', async () => {
    const { store } = await makeStore();
    const gateway = makeGateway();
    const verifier = new LabVerifier({ store, gateway, ownerToken: async () => 'fixture-owner-token' });

    const result = await verifier.verify();

    expect(result.status).toBe('verified');
    if (result.status === 'verified') expect(result.repositoryId).toBe(3003);
    expect(JSON.stringify(result)).not.toContain(marker.controlNonce);
    expect(gateway.calls).toEqual(['resolve', 'read']);
  });

  it('rejects an immutable repository-owner mismatch before reading the marker', async () => {
    const { store } = await makeStore();
    const gateway = makeGateway({ repository: { ...repository, ownerId: 9999 } });
    const verifier = new LabVerifier({ store, gateway, ownerToken: async () => 'fixture-owner-token' });

    await expect(verifier.verify()).resolves.toMatchObject({ status: 'blocked', reason: 'lab_owner_identity_mismatch' });
    expect(gateway.calls).toEqual(['resolve']);
  });

  it('distinguishes missing, public, and marker-mismatch states without exposing raw marker data', async () => {
    const { store } = await makeStore();
    const missing = new LabVerifier({ store, gateway: makeGateway({ marker: 'missing' }), ownerToken: async () => 'fixture-owner-token' });
    await expect(missing.verify()).resolves.toMatchObject({ status: 'missing' });

    const publicRepo = new LabVerifier({
      store,
      gateway: makeGateway({ repository: { ...repository, private: false } }),
      ownerToken: async () => 'fixture-owner-token'
    });
    await expect(publicRepo.verify()).resolves.toMatchObject({ status: 'blocked', reason: 'repository_not_private' });

    const mismatch = new LabVerifier({
      store,
      gateway: makeGateway({ marker: { ...marker, controlNonce: 'different-nonce-1234567890' } }),
      ownerToken: async () => 'fixture-owner-token'
    });
    await expect(mismatch.verify()).resolves.toMatchObject({ status: 'blocked', reason: 'marker_mismatch' });
  });
});

describe('LabVerifier.init', () => {
  it('requires explicit confirmation and never overwrites a different existing marker', async () => {
    const { store } = await makeStore();
    const gateway = makeGateway({ marker: { ...marker, controlNonce: 'different-nonce-1234567890' } });
    const verifier = new LabVerifier({ store, gateway, ownerToken: async () => 'fixture-owner-token' });

    await expect(verifier.init({ repositoryFullName: repository.fullName, confirmed: false })).rejects.toMatchObject({
      code: 'lab_confirmation_required'
    });
    await expect(verifier.init({ repositoryFullName: repository.fullName, confirmed: true })).rejects.toMatchObject({
      code: 'marker_exists_different'
    });
    expect(gateway.calls).toEqual(['resolve', 'read']);
  });

  it('creates, reads back, hashes, and retains a verified marker with a mutation journal', async () => {
    const { store } = await makeStore(false);
    const gateway = makeGateway({ marker: 'missing' });
    const journal = new FakeJournal();
    const verifier = new LabVerifier({ store, gateway, journal, ownerToken: async () => 'fixture-owner-token' });

    const result = await verifier.init({
      repositoryFullName: repository.fullName,
      confirmed: true,
      manifest: manifest()
    });

    expect(result.status).toBe('verified-retained');
    expect(await store.load()).toMatchObject({ manifest: { labId: marker.labId } });
    expect(gateway.calls).toEqual(['resolve', 'read', 'create', 'read']);
    expect(journal.events[0]).toMatch(/^prepare:/);
    expect(journal.events.some((event) => event.startsWith('sent:'))).toBe(true);
    expect(journal.events.some((event) => event.startsWith('verified:'))).toBe(true);
    expect(JSON.stringify(result)).not.toContain('fixture-control-nonce');
  });

  it('rolls back a created marker when local persistence fails and marks dirty if rollback fails', async () => {
    const { store } = await makeStore(false);
    const gateway = makeGateway({ marker: 'missing', deleteFails: true });
    const journal = new FakeJournal();
    const failingStore = {
      load: store.load.bind(store),
      replaceVerified: store.replaceVerified.bind(store),
      async writeNew(): Promise<{ sha256: string }> { throw new Error('local persistence fixture failure'); }
    };
    const failingVerifier = new LabVerifier({
      store: failingStore,
      gateway,
      journal,
      ownerToken: async () => 'fixture-owner-token'
    });

    await expect(failingVerifier.init({ repositoryFullName: repository.fullName, confirmed: true, manifest: manifest() })).rejects.toMatchObject({
      code: 'lab_dirty'
    });
    expect(journal.events.some((event) => event.startsWith('dirty:'))).toBe(true);
  });
});
