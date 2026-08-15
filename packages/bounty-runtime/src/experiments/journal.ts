import { chmod, lstat, mkdir, open, readFile } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';

import {
  sha256StableJson,
  type JsonValue
} from '@aegishub/bounty-core';

import type { ConfigurationMutationEntry } from '../lab/verifier.js';

export type MutationState =
  | 'prepared'
  | 'sent'
  | 'observed'
  | 'outcome-unknown'
  | 'verified-applied'
  | 'verified-not-applied'
  | 'verification-failed'
  | 'cleanup-sent'
  | 'verified-retained'
  | 'clean'
  | 'dirty'
  | 'rolled-back';

export interface JournalMutationEntry {
  readonly entryId: string;
  readonly kind: 'experiment-mutation' | 'lab-marker-create';
  readonly repositoryId: number;
  readonly operationOrdinal?: number;
  readonly catalogId?: string;
  readonly parametersSha256?: string;
  readonly inverseOperationId?: string;
  readonly inverse?: 'delete-marker';
}

export interface JournalRecord {
  readonly sequence: number;
  readonly previousRecordSha256: string | null;
  readonly recordSha256: string;
  readonly timestamp: string;
  readonly runId: string;
  readonly planFingerprint: string;
  readonly entryId: string;
  readonly operationOrdinal: number;
  readonly mutationState: MutationState;
  readonly catalogId: string;
  readonly parametersSha256: string;
  readonly inverseOperationId: string;
  readonly verificationEvidenceId: string | null;
  readonly reason: string | null;
}

export type JournalErrorCode =
  | 'journal_invalid_workspace'
  | 'journal_invalid_run_id'
  | 'journal_invalid_fingerprint'
  | 'journal_exists'
  | 'journal_missing'
  | 'journal_symlink_rejected'
  | 'journal_filesystem_error'
  | 'journal_entry_missing'
  | 'journal_invalid_transition'
  | 'journal_chain_invalid';

export class JournalError extends Error {
  constructor(readonly code: JournalErrorCode) {
    super(code);
    this.name = 'JournalError';
  }
}

export interface WriteAheadMutationJournalOptions {
  readonly workspaceRoot: string;
  readonly runId: string;
  readonly planFingerprint: string;
  readonly now?: () => Date;
}

export class WriteAheadMutationJournal {
  readonly #workspaceRoot: string;
  readonly #runId: string;
  readonly #planFingerprint: string;
  readonly #path: string;
  readonly #now: () => Date;
  readonly #records: JournalRecord[];
  readonly #states = new Map<string, MutationState>();
  #writeChain: Promise<void> = Promise.resolve();

  private constructor(
    options: WriteAheadMutationJournalOptions,
    path: string,
    records: readonly JournalRecord[]
  ) {
    this.#workspaceRoot = resolve(options.workspaceRoot);
    this.#runId = options.runId;
    this.#planFingerprint = options.planFingerprint;
    this.#path = path;
    this.#now = options.now ?? (() => new Date());
    this.#records = [...records];
    for (const record of records) this.#states.set(record.entryId, record.mutationState);
  }

  static async create(options: WriteAheadMutationJournalOptions): Promise<WriteAheadMutationJournal> {
    validateOptions(options);
    const path = await prepareJournalPath(options);
    try {
      const handle = await open(path, 'wx', 0o600);
      try {
        await handle.chmod(0o600);
      } finally {
        await handle.close();
      }
    } catch (error) {
      if (isAlreadyExists(error)) throw new JournalError('journal_exists');
      throw new JournalError('journal_filesystem_error');
    }
    return new WriteAheadMutationJournal(options, path, []);
  }

  static async open(options: WriteAheadMutationJournalOptions): Promise<WriteAheadMutationJournal> {
    validateOptions(options);
    const path = journalPath(options.workspaceRoot, options.runId);
    await rejectSymlink(path);
    let serialized: string;
    try {
      serialized = await readFile(path, 'utf8');
    } catch (error) {
      if (isMissing(error)) throw new JournalError('journal_missing');
      throw new JournalError('journal_filesystem_error');
    }
    const records = parseRecords(serialized, options);
    return new WriteAheadMutationJournal(options, path, records);
  }

  path(): string {
    return this.#path;
  }

  workspaceRoot(): string {
    return this.#workspaceRoot;
  }

  runId(): string {
    return this.#runId;
  }

  records(): readonly JournalRecord[] {
    return this.#records.map((record) => ({ ...record }));
  }

  state(entryId: string): MutationState {
    const current = this.#states.get(entryId);
    if (current === undefined) throw new JournalError('journal_entry_missing');
    return current;
  }

  async prepare(entry: JournalMutationEntry | ConfigurationMutationEntry): Promise<void> {
    return this.transition(entry, 'prepared', null, null);
  }

  async markSent(entryId: string): Promise<void> {
    return this.transitionById(entryId, 'sent', null, null);
  }

  async markObserved(entryId: string, evidenceId: string): Promise<void> {
    return this.transitionById(entryId, 'observed', evidenceId, null);
  }

  async markOutcomeUnknown(entryId: string, reason?: string): Promise<void> {
    return this.transitionById(entryId, 'outcome-unknown', null, reason ?? null);
  }

  async markVerifiedApplied(entryId: string, evidenceId: string): Promise<void> {
    return this.transitionById(entryId, 'verified-applied', evidenceId, null);
  }

  async markVerifiedNotApplied(entryId: string, evidenceId: string): Promise<void> {
    return this.transitionById(entryId, 'verified-not-applied', evidenceId, null);
  }

  async markVerificationFailed(entryId: string, reason: string): Promise<void> {
    return this.transitionById(entryId, 'verification-failed', null, reason);
  }

  async markCleanupSent(entryId: string): Promise<void> {
    return this.transitionById(entryId, 'cleanup-sent', null, null);
  }

  async markClean(entryId: string, evidenceId: string): Promise<void> {
    return this.transitionById(entryId, 'clean', evidenceId, null);
  }

  async markDirty(entryId: string, reason: string): Promise<void> {
    const current = this.state(entryId);
    if (current !== 'verification-failed') await this.markVerificationFailed(entryId, reason);
    await this.transitionById(entryId, 'dirty', null, reason);
  }

  async markVerifiedRetained(entryId: string, evidenceId: string): Promise<void> {
    return this.transitionById(entryId, 'verified-retained', evidenceId, null);
  }

  async markRolledBack(entryId: string): Promise<void> {
    const current = this.state(entryId);
    if (current === 'prepared') {
      await this.transitionById(entryId, 'rolled-back', null, null);
      return;
    }
    if (current === 'sent') {
      await this.markVerifiedNotApplied(entryId, 'rollback-verified');
      await this.markClean(entryId, 'rollback-clean');
      return;
    }
    throw new JournalError('journal_invalid_transition');
  }

  async markVerified(entryId: string): Promise<void> {
    const record = [...this.#records].reverse().find((candidate: JournalRecord) => candidate.entryId === entryId);
    if (record === undefined) throw new JournalError('journal_entry_missing');
    if (record.catalogId === 'configuration.lab-marker-create') {
      await this.markVerifiedRetained(entryId, 'lab-marker-verified');
      return;
    }
    await this.markVerifiedApplied(entryId, 'mutation-verified');
  }

  private async transition(
    entry: JournalMutationEntry | ConfigurationMutationEntry,
    next: MutationState,
    verificationEvidenceId: string | null,
    reason: string | null
  ): Promise<void> {
    const normalized = normalizeEntry(entry);
    await this.enqueue(async () => {
      if (this.#states.has(normalized.entryId)) throw new JournalError('journal_invalid_transition');
      await this.append(normalized, next, verificationEvidenceId, reason);
    });
  }

  private async transitionById(
    entryId: string,
    next: MutationState,
    verificationEvidenceId: string | null,
    reason: string | null
  ): Promise<void> {
    await this.enqueue(async () => {
      const currentRecord = [...this.#records].reverse().find((candidate: JournalRecord) => candidate.entryId === entryId);
      if (currentRecord === undefined) throw new JournalError('journal_entry_missing');
      if (!isAllowedTransition(currentRecord, next)) throw new JournalError('journal_invalid_transition');
      await this.append(currentRecord, next, verificationEvidenceId, reason);
    });
  }

  private async append(
    source: JournalMutationEntry | JournalRecord,
    next: MutationState,
    verificationEvidenceId: string | null,
    reason: string | null
  ): Promise<void> {
    const previous = this.#records.at(-1);
    const unsigned = {
      sequence: this.#records.length + 1,
      previousRecordSha256: previous?.recordSha256 ?? null,
      timestamp: this.#now().toISOString(),
      runId: this.#runId,
      planFingerprint: this.#planFingerprint,
      entryId: source.entryId,
      operationOrdinal: 'operationOrdinal' in source ? source.operationOrdinal ?? 0 : 0,
      mutationState: next,
      catalogId: 'catalogId' in source ? source.catalogId ?? 'configuration.lab-marker-create' : 'unknown',
      parametersSha256: 'parametersSha256' in source
        ? source.parametersSha256 ?? sha256Repository('repositoryId' in source ? source.repositoryId : 0)
        : sha256Repository(0),
      inverseOperationId: 'inverseOperationId' in source
        ? source.inverseOperationId ?? 'github.rest.delete-lab-marker'
        : 'unknown',

      verificationEvidenceId,
      reason
    } as const;
    const record: JournalRecord = {
      ...unsigned,
      recordSha256: sha256StableJson(unsigned as unknown as JsonValue)
    };
    const serialized = `${JSON.stringify(record)}\n`;
    let handle: Awaited<ReturnType<typeof open>> | undefined;
    try {
      handle = await open(this.#path, 'a');
      await handle.write(serialized, null, 'utf8');
      await handle.sync();
      await handle.chmod(0o600);
      this.#records.push(record);
      this.#states.set(record.entryId, record.mutationState);
    } catch {
      throw new JournalError('journal_filesystem_error');
    } finally {
      await handle?.close();
    }
  }

  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const next = this.#writeChain.then(operation, operation);
    this.#writeChain = next.then(() => undefined, () => undefined);
    return next;
  }
}

function normalizeEntry(entry: JournalMutationEntry | ConfigurationMutationEntry): JournalMutationEntry {
  if (entry.kind === 'lab-marker-create') {
    return {
      entryId: entry.entryId,
      kind: 'lab-marker-create',
      repositoryId: entry.repositoryId,
      operationOrdinal: 0,
      catalogId: 'configuration.lab-marker-create',
      parametersSha256: sha256Repository(entry.repositoryId),
      inverseOperationId: 'github.rest.delete-lab-marker'
    };
  }
  return {
    entryId: entry.entryId,
    kind: 'experiment-mutation',
    repositoryId: entry.repositoryId,
    operationOrdinal: entry.operationOrdinal ?? 0,
    catalogId: entry.catalogId ?? 'unknown',
    parametersSha256: entry.parametersSha256 ?? sha256Repository(entry.repositoryId),
    inverseOperationId: entry.inverseOperationId ?? 'unknown'
  };
}

function parseRecords(serialized: string, options: WriteAheadMutationJournalOptions): JournalRecord[] {
  if (serialized.length === 0 || !serialized.endsWith('\n')) throw new JournalError('journal_chain_invalid');
  const lines = serialized.trimEnd().split('\n');
  const records: JournalRecord[] = [];
  for (const [index, line] of lines.entries()) {
    let value: unknown;
    try {
      value = JSON.parse(line) as unknown;
    } catch {
      throw new JournalError('journal_chain_invalid');
    }
    if (!isJournalRecord(value)) throw new JournalError('journal_chain_invalid');
    const expectedPrevious = records.at(-1)?.recordSha256 ?? null;
    if (
      value.sequence !== index + 1 ||
      value.previousRecordSha256 !== expectedPrevious ||
      value.runId !== options.runId ||
      value.planFingerprint !== options.planFingerprint ||
      value.recordSha256 !== sha256StableJson(withoutRecordHash(value))
    ) {
      throw new JournalError('journal_chain_invalid');
    }
    records.push(value);
  }
  replayStates(records);
  return records;
}

function replayStates(records: readonly JournalRecord[]): void {
  const latest = new Map<string, JournalRecord>();
  for (const record of records) {
    const previous = latest.get(record.entryId);
    if (previous === undefined) {
      if (record.mutationState !== 'prepared') throw new JournalError('journal_chain_invalid');
    } else if (!isAllowedTransition(previous, record.mutationState)) {
      throw new JournalError('journal_chain_invalid');
    }
    latest.set(record.entryId, record);
  }
}

function isAllowedTransition(previous: JournalRecord, next: MutationState): boolean {
  const allowed: Record<MutationState, readonly MutationState[]> = {
    prepared: ['sent', 'rolled-back'],
    sent: ['observed', 'outcome-unknown', 'rolled-back', 'verified-retained'],
    observed: ['verified-applied', 'verification-failed'],
    'outcome-unknown': ['verified-applied', 'verified-not-applied', 'verification-failed'],
    'verified-applied': ['cleanup-sent', 'verified-retained', 'verification-failed'],
    'verified-not-applied': ['clean'],
    'verification-failed': ['dirty'],
    'cleanup-sent': ['clean', 'verification-failed'],
    'verified-retained': [],
    clean: [],
    dirty: [],
    'rolled-back': []
  };
  if (next === 'verified-retained' && previous.catalogId !== 'configuration.lab-marker-create') return false;
  return allowed[previous.mutationState].includes(next);
}

function isJournalRecord(value: unknown): value is JournalRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const candidate = value as Record<string, unknown>;
  const states: readonly MutationState[] = [
    'prepared', 'sent', 'observed', 'outcome-unknown', 'verified-applied', 'verified-not-applied',
    'verification-failed', 'cleanup-sent', 'verified-retained', 'clean', 'dirty', 'rolled-back'
  ];
  const keys = Object.keys(candidate).sort().join(',');
  const expected = [
    'catalogId', 'entryId', 'inverseOperationId', 'mutationState', 'operationOrdinal', 'parametersSha256',
    'planFingerprint', 'previousRecordSha256', 'reason', 'recordSha256', 'runId', 'sequence',
    'timestamp', 'verificationEvidenceId'
  ].sort().join(',');
  return keys === expected &&
    Number.isInteger(candidate.sequence) && (candidate.sequence as number) > 0 &&
    (candidate.previousRecordSha256 === null || isSha256(candidate.previousRecordSha256)) &&
    isSha256(candidate.recordSha256) && typeof candidate.timestamp === 'string' &&
    typeof candidate.runId === 'string' && typeof candidate.planFingerprint === 'string' &&
    typeof candidate.entryId === 'string' && Number.isInteger(candidate.operationOrdinal) &&
    typeof candidate.mutationState === 'string' && states.includes(candidate.mutationState as MutationState) &&
    typeof candidate.catalogId === 'string' && isSha256(candidate.parametersSha256) &&
    typeof candidate.inverseOperationId === 'string' &&
    (candidate.verificationEvidenceId === null || typeof candidate.verificationEvidenceId === 'string') &&
    (candidate.reason === null || typeof candidate.reason === 'string');
}

function withoutRecordHash(record: JournalRecord): JsonValue {
  const unsigned = { ...record } as Record<string, JsonValue>;
  delete unsigned.recordSha256;
  return unsigned;
}

function sha256Repository(repositoryId: number): string {
  return sha256StableJson({ repositoryId } as unknown as JsonValue);
}

function validateOptions(options: WriteAheadMutationJournalOptions): void {
  if (typeof options.workspaceRoot !== 'string' || options.workspaceRoot.length === 0 || !isAbsolute(options.workspaceRoot)) {
    throw new JournalError('journal_invalid_workspace');
  }
  if (!/^[0-9a-f-]{36}$/iu.test(options.runId)) throw new JournalError('journal_invalid_run_id');
  if (!isSha256(options.planFingerprint)) throw new JournalError('journal_invalid_fingerprint');
}

async function prepareJournalPath(options: WriteAheadMutationJournalOptions): Promise<string> {
  const root = resolve(options.workspaceRoot);
  const directory = join(root, '.aegishub');
  try {
    await mkdir(directory, { recursive: false, mode: 0o700 });
  } catch (error) {
    if (!isAlreadyExists(error)) throw new JournalError('journal_filesystem_error');
  }
  await rejectSymlink(directory);
  try {
    await chmod(directory, 0o700);
  } catch {
    if (process.platform !== 'win32') throw new JournalError('journal_filesystem_error');
  }
  const path = journalPath(root, options.runId);
  await rejectSymlink(path);
  return path;
}

function journalPath(workspaceRoot: string, runId: string): string {
  return join(resolve(workspaceRoot), '.aegishub', `bounty-run-${runId}.journal.ndjson`);
}

async function rejectSymlink(path: string): Promise<void> {
  try {
    const info = await lstat(path);
    if (info.isSymbolicLink()) throw new JournalError('journal_symlink_rejected');
  } catch (error) {
    if (error instanceof JournalError) throw error;
    if (!isMissing(error)) throw new JournalError('journal_filesystem_error');
  }
}

function isSha256(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/iu.test(value);
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
