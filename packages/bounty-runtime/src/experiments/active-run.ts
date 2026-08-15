import { randomBytes } from 'node:crypto';
import { chmod, lstat, mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import { join } from 'node:path';

import type { JsonValue } from '@aegishub/bounty-core';

import { LabStore } from '../lab/store.js';

const ACTIVE_FILE = 'bounty-active-run.json';
const STOP_FILE = 'bounty-stop-request.json';
const DIRTY_FILE = 'bounty-dirty-state.json';
const JOURNAL_PREFIX = 'bounty-run-';
const JOURNAL_SUFFIX = '.journal.ndjson';

export interface ActiveRunRecord {
  readonly schemaVersion: 1;
  readonly runId: string;
  readonly pid: number;
  readonly leaseNonce: string;
  readonly planFingerprint: string;
  readonly acquiredAt: string;
}

export interface StopRequestRecord {
  readonly schemaVersion: 1;
  readonly runId: string;
  readonly leaseNonce: string;
  readonly requestedAt: string;
}

export interface DirtyStateRecord {
  readonly schemaVersion: 1;
  readonly runId: string;
  readonly repositoryId: number;
  readonly unresolvedMutationOperation: string;
  readonly cleanupOperation: string;
  readonly journalPath: string;
  readonly reason: string;
  readonly recordedAt: string;
}

export type ActiveRunRecovery =
  | { readonly status: 'none' }
  | { readonly status: 'interrupted'; readonly runId: string }
  | { readonly status: 'dirty'; readonly runId: string };

export type ActiveRunErrorCode =
  | 'active_run_exists'
  | 'active_run_invalid'
  | 'active_run_filesystem_error'
  | 'active_run_stop_invalid'
  | 'active_run_not_found'
  | 'active_run_manual_resolution_unverified';

export class ActiveRunError extends Error {
  constructor(readonly code: ActiveRunErrorCode) {
    super(code);
    this.name = 'ActiveRunError';
  }
}

export interface ActiveRunOptions {
  readonly now?: () => Date;
  readonly isProcessAlive?: (pid: number) => boolean | 'ambiguous';
  readonly planFingerprint?: string;
}

export interface StopRequestResult {
  readonly status: 'requested' | 'no-active-run';
  readonly runId?: string;
}

export class ActiveRunLease {
  readonly #store: LabStore;
  readonly #record: ActiveRunRecord;
  readonly #controller = new globalThis.AbortController();
  readonly #recovery: ActiveRunRecovery;
  #finished = false;

  private constructor(store: LabStore, record: ActiveRunRecord, recovery: ActiveRunRecovery) {
    this.#store = store;
    this.#record = record;
    this.#recovery = recovery;
  }

  static async acquire(store: LabStore, runId: string, options: ActiveRunOptions = {}): Promise<ActiveRunLease> {
    const now = options.now ?? (() => new Date());
    const path = statePath(store, ACTIVE_FILE);
    await ensureStateDirectory(store);
    let recovery: ActiveRunRecovery = { status: 'none' };
    try {
      await rejectSymlink(path);
      const existing = parseActive(await readFile(path, 'utf8'));
      const alive = options.isProcessAlive?.(existing.pid) ?? defaultIsProcessAlive(existing.pid);
      if (alive === true || alive === 'ambiguous') throw new ActiveRunError('active_run_exists');
      recovery = await recoverDeadRun(store, existing, now);
      await removeMatchingStop(store, existing);
      await rm(path, { force: true });
    } catch (error) {
      if (error instanceof ActiveRunError) throw error;
      if (!isMissing(error)) throw new ActiveRunError('active_run_filesystem_error');
    }

    const record: ActiveRunRecord = {
      schemaVersion: 1,
      runId: validateRunId(runId),
      pid: process.pid,
      leaseNonce: randomBytes(24).toString('base64url'),
      planFingerprint: validateFingerprint(options.planFingerprint ?? '0'.repeat(64)),
      acquiredAt: now().toISOString()
    };
    try {
      const handle = await open(path, 'wx', 0o600);
      try {
        await handle.write(`${JSON.stringify(record)}\n`, null, 'utf8');
        await handle.sync();
        await handle.chmod(0o600);
      } finally {
        await handle.close();
      }
    } catch (error) {
      if (isAlreadyExists(error)) throw new ActiveRunError('active_run_exists');
      throw new ActiveRunError('active_run_filesystem_error');
    }
    return new ActiveRunLease(store, record, recovery);
  }

  signal(): globalThis.AbortSignal {
    return this.#controller.signal;
  }

  recovery(): ActiveRunRecovery {
    return this.#recovery;
  }

  async pollStopRequest(): Promise<void> {
    if (this.#finished) return;
    const path = statePath(this.#store, STOP_FILE);
    try {
      await rejectSymlink(path);
      const request = parseStop(await readFile(path, 'utf8'));
      if (request.runId === this.#record.runId && request.leaseNonce === this.#record.leaseNonce) {
        this.#controller.abort();
      }
    } catch (error) {
      if (isMissing(error)) return;
      if (error instanceof ActiveRunError) throw error;
      throw new ActiveRunError('active_run_stop_invalid');
    }
  }

  async finish(): Promise<void> {
    if (this.#finished) return;
    this.#finished = true;
    const activePath = statePath(this.#store, ACTIVE_FILE);
    const stopPath = statePath(this.#store, STOP_FILE);
    try {
      await rejectSymlink(activePath);
      const current = parseActive(await readFile(activePath, 'utf8'));
      if (current.runId === this.#record.runId && current.leaseNonce === this.#record.leaseNonce) {
        await rm(activePath, { force: true });
      }
      await rejectSymlink(stopPath);
      const stop = parseStop(await readFile(stopPath, 'utf8'));
      if (stop.runId === this.#record.runId && stop.leaseNonce === this.#record.leaseNonce) await rm(stopPath, { force: true });
    } catch (error) {
      if (isMissing(error)) return;
      if (error instanceof ActiveRunError) throw error;
      throw new ActiveRunError('active_run_filesystem_error');
    }
  }

  installSignalHandlers(onStop?: () => void): () => void {
    const handler = () => {
      this.#controller.abort();
      onStop?.();
    };
    process.once('SIGINT', handler);
    process.once('SIGTERM', handler);
    return () => {
      process.off('SIGINT', handler);
      process.off('SIGTERM', handler);
    };
  }
}

export async function requestEmergencyStop(store: LabStore, now: () => Date = () => new Date()): Promise<StopRequestResult> {
  const activePath = statePath(store, ACTIVE_FILE);
  let active: ActiveRunRecord;
  try {
    await rejectSymlink(activePath);
    active = parseActive(await readFile(activePath, 'utf8'));
  } catch (error) {
    if (isMissing(error)) return { status: 'no-active-run' };
    if (error instanceof ActiveRunError) throw error;
    throw new ActiveRunError('active_run_filesystem_error');
  }
  const stop: StopRequestRecord = {
    schemaVersion: 1,
    runId: active.runId,
    leaseNonce: active.leaseNonce,
    requestedAt: now().toISOString()
  };
  const path = statePath(store, STOP_FILE);
  await rejectSymlink(path);
  try {
    const handle = await open(path, 'wx', 0o600);
    try {
      await handle.write(`${JSON.stringify(stop)}\n`, null, 'utf8');
      await handle.sync();
      await handle.chmod(0o600);
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (isAlreadyExists(error)) {
      await atomicStateWrite(path, stop as unknown as JsonValue);
      return { status: 'requested', runId: active.runId };
    }
    throw new ActiveRunError('active_run_filesystem_error');
  }
  return { status: 'requested', runId: active.runId };
}

export class DirtyStateStore {
  readonly #store: LabStore;
  readonly #now: () => Date;

  constructor(store: LabStore, now: () => Date = () => new Date()) {
    this.#store = store;
    this.#now = now;
  }

  async load(): Promise<DirtyStateRecord | undefined> {
    const path = statePath(this.#store, DIRTY_FILE);
    try {
      await rejectSymlink(path);
      return parseDirty(await readFile(path, 'utf8'));
    } catch (error) {
      if (isMissing(error)) return undefined;
      if (error instanceof ActiveRunError) throw error;
      throw new ActiveRunError('active_run_filesystem_error');
    }
  }

  async markDirty(input: Omit<DirtyStateRecord, 'schemaVersion' | 'recordedAt'>): Promise<DirtyStateRecord> {
    await ensureStateDirectory(this.#store);
    const record: DirtyStateRecord = { schemaVersion: 1, ...input, recordedAt: this.#now().toISOString() };
    const path = statePath(this.#store, DIRTY_FILE);
    await rejectSymlink(path);
    await atomicStateWrite(path, record as unknown as JsonValue);
    return record;
  }

  async clearAfterVerification(input: { readonly labVerified: boolean; readonly catalogVerified: boolean }): Promise<void> {
    if (!input.labVerified || !input.catalogVerified) throw new ActiveRunError('active_run_manual_resolution_unverified');
    const path = statePath(this.#store, DIRTY_FILE);
    await rejectSymlink(path);
    try {
      await rm(path, { force: true });
    } catch {
      throw new ActiveRunError('active_run_filesystem_error');
    }
  }
}

async function removeMatchingStop(store: LabStore, record: ActiveRunRecord): Promise<void> {
  const path = statePath(store, STOP_FILE);
  try {
    await rejectSymlink(path);
    const stop = parseStop(await readFile(path, 'utf8'));
    if (stop.runId === record.runId && stop.leaseNonce === record.leaseNonce) await rm(path, { force: true });
  } catch (error) {
    if (isMissing(error)) return;
    if (error instanceof ActiveRunError) throw error;
    throw new ActiveRunError('active_run_filesystem_error');
  }
}

async function recoverDeadRun(store: LabStore, record: ActiveRunRecord, now: () => Date): Promise<ActiveRunRecovery> {
  const journalPath = statePath(store, `${JOURNAL_PREFIX}${record.runId}${JOURNAL_SUFFIX}`);
  let serialized: string;
  try {
    serialized = await readFile(journalPath, 'utf8');
  } catch (error) {
    if (isMissing(error)) return { status: 'interrupted', runId: record.runId };
    throw new ActiveRunError('active_run_filesystem_error');
  }
  const lines = serialized.trim().split('\n').filter((line) => line.length > 0);
  const last = lines.at(-1);
  if (last === undefined) return { status: 'interrupted', runId: record.runId };
  let value: unknown;
  try {
    value = JSON.parse(last) as unknown;
  } catch {
    throw new ActiveRunError('active_run_filesystem_error');
  }
  if (!isRecord(value)) throw new ActiveRunError('active_run_filesystem_error');
  const mutationState = value.mutationState;
  const unresolved = typeof mutationState === 'string' && !['clean', 'rolled-back', 'verified-not-applied', 'verified-retained'].includes(mutationState);
  if (!unresolved) return { status: 'interrupted', runId: record.runId };
  const dirty = new DirtyStateStore(store, now);
  await dirty.markDirty({
    runId: record.runId,
    repositoryId: typeof value.repositoryId === 'number' ? value.repositoryId : 0,
    unresolvedMutationOperation: typeof value.catalogId === 'string' ? value.catalogId : 'unknown',
    cleanupOperation: typeof value.inverseOperationId === 'string' ? value.inverseOperationId : 'unknown',
    journalPath,
    reason: `interrupted_${mutationState}`
  });
  return { status: 'dirty', runId: record.runId };
}

async function ensureStateDirectory(store: LabStore, create = true): Promise<void> {
  const directory = join(store.workspaceRoot(), '.aegishub');
  try {
    const info = await lstat(directory);
    if (info.isSymbolicLink() || !info.isDirectory()) throw new ActiveRunError('active_run_filesystem_error');
  } catch (error) {
    if (error instanceof ActiveRunError) throw error;
    if (!isMissing(error) || !create) {
      if (!create && isMissing(error)) throw error;
      throw new ActiveRunError('active_run_filesystem_error');
    }
    try {
      await mkdir(directory, { recursive: false, mode: 0o700 });
    } catch (mkdirError) {
      if (!isAlreadyExists(mkdirError)) throw new ActiveRunError('active_run_filesystem_error');
    }
  }
  await chmod(directory, 0o700);
}

async function atomicStateWrite(path: string, value: JsonValue): Promise<void> {
  const temporary = `${path}.${randomBytes(12).toString('hex')}.tmp`;
  try {
    const handle = await open(temporary, 'wx', 0o600);
    try {
      await handle.write(`${JSON.stringify(value)}\n`, null, 'utf8');
      await handle.sync();
      await handle.chmod(0o600);
    } finally {
      await handle.close();
    }
    await rename(temporary, path);
  } catch {
    await rm(temporary, { force: true }).catch(() => undefined);
    throw new ActiveRunError('active_run_filesystem_error');
  }
}

function statePath(store: LabStore, file: string): string {
  return store.statePath(file);
}

function parseActive(serialized: string): ActiveRunRecord {
  const value = parseJson(serialized);
  if (!isRecord(value) || Object.keys(value).sort().join(',') !== 'acquiredAt,leaseNonce,pid,planFingerprint,runId,schemaVersion' || value.schemaVersion !== 1 || typeof value.runId !== 'string' || typeof value.pid !== 'number' || !Number.isSafeInteger(value.pid) || value.pid < 1 || typeof value.leaseNonce !== 'string' || value.leaseNonce.length < 16 || typeof value.planFingerprint !== 'string' || typeof value.acquiredAt !== 'string') {
    throw new ActiveRunError('active_run_invalid');
  }
  return value as unknown as ActiveRunRecord;
}

function parseStop(serialized: string): StopRequestRecord {
  const value = parseJson(serialized);
  if (!isRecord(value) || Object.keys(value).sort().join(',') !== 'leaseNonce,requestedAt,runId,schemaVersion' || value.schemaVersion !== 1 || typeof value.runId !== 'string' || typeof value.leaseNonce !== 'string' || value.leaseNonce.length < 16 || typeof value.requestedAt !== 'string') throw new ActiveRunError('active_run_stop_invalid');
  return value as unknown as StopRequestRecord;
}

function parseDirty(serialized: string): DirtyStateRecord {
  const value = parseJson(serialized);
  if (!isRecord(value) || Object.keys(value).sort().join(',') !== 'cleanupOperation,journalPath,reason,recordedAt,repositoryId,runId,schemaVersion,unresolvedMutationOperation' || value.schemaVersion !== 1 || typeof value.runId !== 'string' || typeof value.repositoryId !== 'number' || typeof value.unresolvedMutationOperation !== 'string' || typeof value.cleanupOperation !== 'string' || typeof value.journalPath !== 'string' || typeof value.reason !== 'string' || typeof value.recordedAt !== 'string') throw new ActiveRunError('active_run_invalid');
  return value as unknown as DirtyStateRecord;
}

function parseJson(serialized: string): unknown {
  try {
    if (!serialized.endsWith('\n')) throw new Error('not newline terminated');
    return JSON.parse(serialized) as unknown;
  } catch {
    throw new ActiveRunError('active_run_invalid');
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validateRunId(value: string): string {
  if (!/^[0-9a-f-]{36}$/iu.test(value)) throw new ActiveRunError('active_run_invalid');
  return value;
}

function validateFingerprint(value: string): string {
  if (!/^[0-9a-f]{64}$/iu.test(value)) throw new ActiveRunError('active_run_invalid');
  return value;
}

async function rejectSymlink(path: string): Promise<void> {
  try {
    const info = await lstat(path);
    if (info.isSymbolicLink()) throw new ActiveRunError('active_run_filesystem_error');
  } catch (error) {
    if (error instanceof ActiveRunError) throw error;
    if (!isMissing(error)) throw new ActiveRunError('active_run_filesystem_error');
  }
}

function defaultIsProcessAlive(pid: number): boolean | 'ambiguous' {
  if (pid === process.pid) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (isNodeError(error, 'ESRCH')) return false;
    return 'ambiguous';
  }
}

function isMissing(error: unknown): boolean {
  return isNodeError(error, 'ENOENT');
}

function isAlreadyExists(error: unknown): boolean {
  return isNodeError(error, 'EEXIST');
}

function isNodeError(error: unknown, code: string): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && (error as { code?: unknown }).code === code;
}
