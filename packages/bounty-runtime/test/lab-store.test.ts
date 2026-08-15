import { mkdtemp, readFile, stat, symlink, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';
import type { LabManifest } from '@aegishub/bounty-core';

import { LabStore, LabStoreError } from '../src/lab/store.js';

const timestamp = '2026-08-13T12:00:00.000Z';

function manifest(overrides: Partial<LabManifest> = {}): LabManifest {
  return {
    schemaVersion: 1,
    labId: '95f38cca-42e2-4b7d-82e6-f13f4549b2f3',
    githubHost: 'github.com',
    owner: { id: 1001, nodeId: 'U_owner_fixture', login: 'owner-fixture' },
    researcher: { id: 2002, nodeId: 'U_researcher_fixture', login: 'researcher-fixture' },
    repositories: [
      {
        id: 3003,
        nodeId: 'R_lab_fixture',
        ownerId: 1001,
        owner: 'owner-fixture',
        name: 'lab-fixture',
        fullName: 'owner-fixture/lab-fixture',
        markerSha256: 'a'.repeat(64)
      }
    ],
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

describe('LabStore', () => {
  it('uses the fixed .aegishub manifest path and returns a stable hash', async () => {
    const workspace = await mkdtemp(join(tmpdir(), 'aegishub-lab-store-'));
    const store = new LabStore(workspace);

    const written = await store.writeNew(manifest());
    const loaded = await store.load();

    expect(store.statePath('bounty-lab.json')).toBe(join(workspace, '.aegishub', 'bounty-lab.json'));
    expect(loaded.manifest).toEqual(manifest());
    expect(loaded.sha256).toBe(written.sha256);
  });

  it('writes through a sibling temporary file and refuses overwrite', async () => {
    const workspace = await mkdtemp(join(tmpdir(), 'aegishub-lab-store-'));
    const store = new LabStore(workspace);

    await store.writeNew(manifest());
    await expect(store.writeNew(manifest())).rejects.toMatchObject({ code: 'lab_manifest_exists' });
    const content = await readFile(join(workspace, '.aegishub', 'bounty-lab.json'), 'utf8');
    expect(JSON.parse(content)).toEqual(manifest());
  });

  it('performs compare-and-swap replacement and rejects a stale expected hash', async () => {
    const workspace = await mkdtemp(join(tmpdir(), 'aegishub-lab-store-'));
    const store = new LabStore(workspace);
    const first = await store.writeNew(manifest());

    const changed = manifest({ verifiedAt: '2026-08-13T13:00:00.000Z' });
    const replaced = await store.replaceVerified(first.sha256, changed);
    expect(replaced.sha256).not.toBe(first.sha256);
    await expect(store.replaceVerified(first.sha256, manifest())).rejects.toMatchObject({ code: 'lab_manifest_conflict' });
  });

  it('rejects malformed and unknown manifest fields before persistence', async () => {
    const workspace = await mkdtemp(join(tmpdir(), 'aegishub-lab-store-'));
    const store = new LabStore(workspace);
    await expect(store.writeNew({ ...manifest(), unknown: true } as never)).rejects.toMatchObject({
      code: 'invalid_lab_manifest'
    });
    await expect(store.load()).rejects.toMatchObject({ code: 'lab_manifest_missing' });
  });

  it('rejects traversal and absolute segments from statePath', async () => {
    const workspace = await mkdtemp(join(tmpdir(), 'aegishub-lab-store-'));
    const store = new LabStore(workspace);

    expect(() => store.statePath('..', 'outside')).toThrowError(new LabStoreError('invalid_lab_state_path'));
    expect(() => store.statePath('/tmp', 'outside')).toThrowError(new LabStoreError('invalid_lab_state_path'));
    expect(() => store.statePath('contains\u0000null')).toThrowError(new LabStoreError('invalid_lab_state_path'));
  });

  it('rejects a symlink at the state directory or manifest path', async () => {
    const workspace = await mkdtemp(join(tmpdir(), 'aegishub-lab-store-'));
    const store = new LabStore(workspace);
    const target = await mkdtemp(join(tmpdir(), 'aegishub-lab-target-'));
    await symlink(target, join(workspace, '.aegishub'));

    await expect(store.writeNew(manifest())).rejects.toMatchObject({ code: 'lab_symlink_rejected' });

    const workspaceTwo = await mkdtemp(join(tmpdir(), 'aegishub-lab-store-'));
    const storeTwo = new LabStore(workspaceTwo);
    await storeTwo.writeNew(manifest());
    const manifestPath = join(workspaceTwo, '.aegishub', 'bounty-lab.json');
    const regular = `${manifestPath}.regular`;
    await writeFile(regular, await readFile(manifestPath));
    await unlink(manifestPath);
    await symlink(regular, manifestPath);
    await expect(storeTwo.load()).rejects.toMatchObject({ code: 'lab_symlink_rejected' });
  });

  it('uses restrictive POSIX modes when supported', async () => {
    const workspace = await mkdtemp(join(tmpdir(), 'aegishub-lab-store-'));
    const store = new LabStore(workspace);
    await store.writeNew(manifest());
    const directoryMode = (await stat(join(workspace, '.aegishub'))).mode & 0o777;
    const fileMode = (await stat(join(workspace, '.aegishub', 'bounty-lab.json'))).mode & 0o777;
    if (process.platform !== 'win32') {
      expect(directoryMode).toBe(0o700);
      expect(fileMode).toBe(0o600);
    }
  });
});
