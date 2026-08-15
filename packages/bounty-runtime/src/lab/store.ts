import { chmod, lstat, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { randomUUID } from 'node:crypto';

import { labManifestSchema, sha256StableJson, stableJson, type JsonValue, type LabManifest } from '@aegishub/bounty-core';

const STATE_DIRECTORY = '.aegishub';
const MANIFEST_FILE = 'bounty-lab.json';

export type LabStoreErrorCode =
  | 'invalid_lab_workspace'
  | 'invalid_lab_state_path'
  | 'lab_manifest_missing'
  | 'lab_manifest_exists'
  | 'lab_manifest_conflict'
  | 'invalid_lab_manifest'
  | 'lab_symlink_rejected'
  | 'lab_filesystem_error';

export class LabStoreError extends Error {
  constructor(readonly code: LabStoreErrorCode) {
    super(code);
    this.name = 'LabStoreError';
  }
}

export class LabStore {
  readonly #workspaceRoot: string;

  constructor(workspaceRoot: string) {
    if (typeof workspaceRoot !== 'string' || workspaceRoot.length === 0 || !isAbsolute(workspaceRoot)) {
      throw new LabStoreError('invalid_lab_workspace');
    }
    this.#workspaceRoot = resolve(workspaceRoot);
  }

  async load(): Promise<{ manifest: LabManifest; sha256: string }> {
    const manifestPath = this.manifestPath();
    await this.ensureStateDirectory(false);
    await this.rejectSymlink(manifestPath);

    let serialized: string;
    try {
      serialized = await readFile(manifestPath, 'utf8');
    } catch (error) {
      if (isMissing(error)) throw new LabStoreError('lab_manifest_missing');
      throw new LabStoreError('lab_filesystem_error');
    }
    const manifest = parseManifest(serialized);
    return { manifest, sha256: sha256StableJson(toJsonManifest(manifest)) };
  }

  async writeNew(manifest: LabManifest): Promise<{ sha256: string }> {
    const parsed = parseManifestValue(manifest);
    const directory = await this.ensureStateDirectory(true);
    const manifestPath = join(directory, MANIFEST_FILE);
    await this.rejectSymlink(manifestPath);
    if (await exists(manifestPath)) throw new LabStoreError('lab_manifest_exists');

    const sha256 = sha256StableJson(toJsonManifest(parsed));
    await this.atomicWrite(manifestPath, parsed, directory);
    return { sha256 };
  }

  async replaceVerified(expectedSha256: string, manifest: LabManifest): Promise<{ sha256: string }> {
    if (!/^[a-f0-9]{64}$/iu.test(expectedSha256)) {
      throw new LabStoreError('lab_manifest_conflict');
    }
    const current = await this.load();
    if (current.sha256 !== expectedSha256) throw new LabStoreError('lab_manifest_conflict');

    const parsed = parseManifestValue(manifest);
    const sha256 = sha256StableJson(toJsonManifest(parsed));
    await this.atomicWrite(this.manifestPath(), parsed, this.stateDirectory());
    return { sha256 };
  }

  workspaceRoot(): string {
    return this.#workspaceRoot;
  }

  statePath(...segments: readonly string[]): string {
    if (segments.length === 0 || segments.some((segment) => !isSafeSegment(segment))) {
      throw new LabStoreError('invalid_lab_state_path');
    }
    const stateDirectory = this.stateDirectory();
    const candidate = resolve(stateDirectory, ...segments);
    const rel = relative(stateDirectory, candidate);
    if (rel === '' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
      throw new LabStoreError('invalid_lab_state_path');
    }
    return candidate;
  }

  private stateDirectory(): string {
    return join(this.#workspaceRoot, STATE_DIRECTORY);
  }

  private manifestPath(): string {
    return join(this.stateDirectory(), MANIFEST_FILE);
  }

  private async ensureStateDirectory(create: boolean): Promise<string> {
    const directory = this.stateDirectory();
    try {
      const existing = await lstat(directory);
      if (existing.isSymbolicLink()) throw new LabStoreError('lab_symlink_rejected');
      if (!existing.isDirectory()) throw new LabStoreError('lab_filesystem_error');
    } catch (error) {
      if (error instanceof LabStoreError) throw error;
      if (!isMissing(error) || !create) throw new LabStoreError(create ? 'lab_filesystem_error' : 'lab_manifest_missing');
      try {
        await mkdir(directory, { recursive: false, mode: 0o700 });
      } catch {
        throw new LabStoreError('lab_filesystem_error');
      }
      await this.rejectSymlink(directory);
    }
    try {
      await chmod(directory, 0o700);
    } catch {
      if (process.platform !== 'win32') throw new LabStoreError('lab_filesystem_error');
    }
    return directory;
  }

  private async rejectSymlink(path: string): Promise<void> {
    try {
      const info = await lstat(path);
      if (info.isSymbolicLink()) throw new LabStoreError('lab_symlink_rejected');
    } catch (error) {
      if (error instanceof LabStoreError) throw error;
      if (!isMissing(error)) throw new LabStoreError('lab_filesystem_error');
    }
  }

  private async atomicWrite(path: string, manifest: LabManifest, directory: string): Promise<void> {
    const temporaryPath = join(directory, `.${MANIFEST_FILE}.${randomUUID()}.tmp`);
    const serialized = `${stableJson(toJsonManifest(manifest))}\n`;
    try {
      await writeFile(temporaryPath, serialized, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
      try {
        await chmod(temporaryPath, 0o600);
      } catch {
        if (process.platform !== 'win32') throw new LabStoreError('lab_filesystem_error');
      }
      await rejectSymlinkPath(temporaryPath);
      await rename(temporaryPath, path);
      try {
        await chmod(path, 0o600);
      } catch {
        if (process.platform !== 'win32') throw new LabStoreError('lab_filesystem_error');
      }
    } catch (error) {
      try {
        await rm(temporaryPath, { force: true });
      } catch {
        // Preserve the original closed error.
      }
      if (error instanceof LabStoreError) throw error;
      throw new LabStoreError('lab_filesystem_error');
    }
  }
}

function toJsonManifest(manifest: LabManifest): JsonValue {
  return JSON.parse(JSON.stringify(manifest)) as JsonValue;
}

function parseManifest(serialized: string): LabManifest {
  let value: unknown;
  try {
    value = JSON.parse(serialized) as unknown;
  } catch {
    throw new LabStoreError('invalid_lab_manifest');
  }
  return parseManifestValue(value);
}

function parseManifestValue(value: unknown): LabManifest {
  const parsed = labManifestSchema.safeParse(value);
  if (!parsed.success) throw new LabStoreError('invalid_lab_manifest');
  return parsed.data;
}

function isSafeSegment(segment: string): boolean {
  return typeof segment === 'string' && segment.length > 0 && segment !== '.' && segment !== '..' && !isAbsolute(segment) && !segment.includes('/') && !segment.includes('\\') && !segment.includes('\u0000');
}

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (isMissing(error)) return false;
    throw new LabStoreError('lab_filesystem_error');
  }
}

async function rejectSymlinkPath(path: string): Promise<void> {
  const info = await lstat(path);
  if (info.isSymbolicLink()) throw new LabStoreError('lab_symlink_rejected');
}

function isMissing(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT';
}
