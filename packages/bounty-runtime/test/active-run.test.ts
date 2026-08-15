import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { LabStore } from '../src/lab/store.js';
import {
  ActiveRunLease,
  ActiveRunError,
  requestEmergencyStop,
  DirtyStateStore,
  type ActiveRunRecord
} from '../src/experiments/active-run.js';

const runId = '3e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12';
const oldRunId = '9e4b4e32-e69d-4b59-92ed-5b0e0b4f4f4f';
const fingerprint = 'b'.repeat(64);

async function storeFixture() {
  return new LabStore(await mkdtemp(join(tmpdir(), 'aegishub-active-run-')));
}

async function writeActive(store: LabStore, record: ActiveRunRecord): Promise<void> {
  await mkdir(join(store.workspaceRoot(), '.aegishub'), { recursive: true, mode: 0o700 });
  await writeFile(store.statePath('bounty-active-run.json'), `${JSON.stringify(record)}\n`, { mode: 0o600, flag: 'wx' });
}

describe('ActiveRunLease', () => {
  it('exclusively acquires one lease, blocks a second owner, and removes active/stop state on finish', async () => {
    const store = await storeFixture();
    const lease = await ActiveRunLease.acquire(store, runId, { isProcessAlive: () => true });

    await expect(ActiveRunLease.acquire(store, oldRunId, { isProcessAlive: () => true })).rejects.toMatchObject({
      code: 'active_run_exists'
    });
    const stop = await requestEmergencyStop(store);
    expect(stop.status).toBe('requested');
    await lease.pollStopRequest();
    expect(lease.signal().aborted).toBe(true);

    await lease.finish();
    await expect(requestEmergencyStop(store)).resolves.toMatchObject({ status: 'no-active-run' });
  });

  it('ignores a stale stop request whose run and lease nonce do not match', async () => {
    const store = await storeFixture();
    const lease = await ActiveRunLease.acquire(store, runId, { isProcessAlive: () => true });
    await writeFile(store.statePath('bounty-stop-request.json'), `${JSON.stringify({ schemaVersion: 1, runId, leaseNonce: 'wrong-lease-nonce-1234', requestedAt: '2026-08-13T12:00:00.000Z' })}\n`, { mode: 0o600 });

    await lease.pollStopRequest();
    expect(lease.signal().aborted).toBe(false);
    await lease.finish();
  });

  it('recovers a definitely dead run with no sent mutation as interrupted', async () => {
    const store = await storeFixture();
    await writeActive(store, {
      schemaVersion: 1,
      runId: oldRunId,
      pid: 999_999,
      leaseNonce: 'old-lease-nonce-1234567890',
      planFingerprint: fingerprint,
      acquiredAt: '2026-08-13T12:00:00.000Z'
    });

    const lease = await ActiveRunLease.acquire(store, runId, { isProcessAlive: () => false });
    expect(lease.recovery()).toEqual({ status: 'interrupted', runId: oldRunId });
    await lease.finish();
  });

  it('marks a dead run dirty before recovering a lease when its journal has an unresolved mutation', async () => {
    const store = await storeFixture();
    await writeActive(store, {
      schemaVersion: 1,
      runId: oldRunId,
      pid: 999_999,
      leaseNonce: 'old-lease-nonce-1234567890',
      planFingerprint: fingerprint,
      acquiredAt: '2026-08-13T12:00:00.000Z'
    });
    const journalPath = store.statePath(`bounty-run-${oldRunId}.journal.ndjson`);
    const first = {
      sequence: 1,
      previousRecordSha256: null,
      recordSha256: 'c'.repeat(64),
      timestamp: '2026-08-13T12:00:00.000Z',
      runId: oldRunId,
      planFingerprint: fingerprint,
      entryId: 'mutation-1',
      operationOrdinal: 1,
      mutationState: 'sent',
      catalogId: 'github.rest.put-lab-marker',
      parametersSha256: 'a'.repeat(64),
      inverseOperationId: 'github.rest.delete-lab-marker',
      verificationEvidenceId: null,
      reason: null
    };
    await writeFile(journalPath, `${JSON.stringify(first)}\n`, { mode: 0o600 });

    const lease = await ActiveRunLease.acquire(store, runId, { isProcessAlive: () => false });
    expect(lease.recovery()).toEqual({ status: 'dirty', runId: oldRunId });
    await expect(new DirtyStateStore(store).load()).resolves.toMatchObject({
      runId: oldRunId,
      unresolvedMutationOperation: 'github.rest.put-lab-marker',
      cleanupOperation: 'github.rest.delete-lab-marker'
    });
    await lease.finish();
  });

  it('requires both lab and catalog verification before clearing dirty state', async () => {
    const store = await storeFixture();
    const dirty = new DirtyStateStore(store);
    await dirty.markDirty({
      runId,
      repositoryId: 3003,
      unresolvedMutationOperation: 'github.rest.contents.put-lab-marker.v1',
      cleanupOperation: 'github.rest.contents.delete-lab-marker.v1',
      journalPath: store.statePath('bounty-run-dirty.journal.ndjson'),
      reason: 'cleanup_failed'
    });

    await expect(dirty.clearAfterVerification({ labVerified: true, catalogVerified: false })).rejects.toMatchObject({
      code: 'active_run_manual_resolution_unverified'
    });
    await dirty.clearAfterVerification({ labVerified: true, catalogVerified: true });
    await expect(dirty.load()).resolves.toBeUndefined();
  });

  it('treats an ambiguous or permission-denied PID probe as active', async () => {
    const store = await storeFixture();
    await writeActive(store, {
      schemaVersion: 1,
      runId: oldRunId,
      pid: 1234,
      leaseNonce: 'old-lease-nonce-1234567890',
      planFingerprint: fingerprint,
      acquiredAt: '2026-08-13T12:00:00.000Z'
    });

    await expect(ActiveRunLease.acquire(store, runId, {
      isProcessAlive: () => 'ambiguous'
    })).rejects.toEqual(new ActiveRunError('active_run_exists'));
  });
});
