import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  FIXED_POLICY_ENFORCEMENT_SHA256,
  policyFingerprint,
  policySnapshotSchema,
  type PolicySnapshot
} from '@aegishub/bounty-core';

import type {
  FetchPolicySourceForReviewInput,
  PolicySourceClientDependencies,
  PolicySourceId,
  PolicySourceReviewResult,
  PolicySourceUrl
} from '../src/policy/source-client.js';
import { fetchPolicySourceForReview, POLICY_SOURCES } from '../src/policy/source-client.js';
import {
  REVIEWED_POLICY_SNAPSHOT_DIRECTORY,
  REVIEWED_POLICY_SNAPSHOT_PATH
} from '../src/policy/snapshot.js';

export { REVIEWED_POLICY_SNAPSHOT_PATH } from '../src/policy/snapshot.js';

/** The direct-script adapter is bound to the shared fail-closed source transport. */
export const reviewPolicyTransport: (
  input: FetchPolicySourceForReviewInput
) => Promise<PolicySourceReviewResult> = fetchPolicySourceForReview;

export type PolicyReviewErrorCode =
  | 'unimplemented_policy_review'
  | 'invalid_policy_review_arguments'
  | 'invalid_policy_review_snapshot'
  | 'invalid_policy_review_sources'
  | 'invalid_policy_review_filesystem';

export class PolicyReviewError extends Error {
  constructor(readonly code: PolicyReviewErrorCode) {
    super(code);
    this.name = 'PolicyReviewError';
  }
}

export type PolicyReviewFetchResult = PolicySourceReviewResult;

export interface PolicyReviewFileSystem {
  readFile(path: typeof REVIEWED_POLICY_SNAPSHOT_PATH): Promise<string | undefined>;
  writeTemporaryFile(directory: typeof REVIEWED_POLICY_SNAPSHOT_DIRECTORY, contents: string): Promise<string>;
  renameTemporaryFile(tempPath: string, destination: typeof REVIEWED_POLICY_SNAPSHOT_PATH): Promise<void>;
}

export interface ReviewPolicyInput {
  readonly args: readonly string[];
  readonly fetchSource: (source: {
    readonly id: PolicySourceId;
    readonly url: PolicySourceUrl;
  }) => Promise<PolicyReviewFetchResult>;
  readonly fileSystem: PolicyReviewFileSystem;
  readonly writeOutput: (line: string) => void;
}

export type ReviewPolicyResult =
  | {
      readonly mode: 'preview';
      readonly currentSnapshot?: Readonly<PolicySnapshot>;
      readonly candidates: readonly PolicyReviewFetchResult[];
    }
  | {
      readonly mode: 'write';
      readonly snapshot: Readonly<PolicySnapshot>;
    };

export interface ReviewPolicyCliAdapter {
  run(input: ReviewPolicyInput): Promise<ReviewPolicyResult>;
}

export interface ReviewPolicyCliDependencies {
  readonly argv: readonly string[];
  readonly sourceClientDependencies: PolicySourceClientDependencies;
  readonly fileSystem: PolicyReviewFileSystem;
  readonly writeOutput: (line: string) => void;
}

/** Concrete Node adapter shape; callers inject the only I/O primitives used by the CLI. */
export interface NodeReviewPolicyRuntime {
  readonly argv: readonly string[];
  readonly sourceClientDependencies: PolicySourceClientDependencies;
  readonly readFile: (path: typeof REVIEWED_POLICY_SNAPSHOT_PATH) => Promise<string | undefined>;
  readonly writeTemporaryFile: (
    directory: typeof REVIEWED_POLICY_SNAPSHOT_DIRECTORY,
    contents: string
  ) => Promise<string>;
  readonly renameTemporaryFile: (
    tempPath: string,
    destination: typeof REVIEWED_POLICY_SNAPSHOT_PATH
  ) => Promise<void>;
  readonly writeOutput: (line: string) => void;
}

export function createNodeReviewPolicyCliDependencies(
  runtime: NodeReviewPolicyRuntime
): ReviewPolicyCliDependencies {
  return {
    argv: runtime.argv,
    sourceClientDependencies: runtime.sourceClientDependencies,
    fileSystem: {
      readFile: runtime.readFile,
      writeTemporaryFile: runtime.writeTemporaryFile,
      renameTemporaryFile: runtime.renameTemporaryFile
    },
    writeOutput: runtime.writeOutput
  };
}

export async function reviewPolicy(input: ReviewPolicyInput): Promise<ReviewPolicyResult> {
  const existing = await readExistingSnapshot(input.fileSystem);
  const reviewedAt = parseReviewArguments(input.args, existing);
  if (reviewedAt !== undefined && existing === undefined) {
    throw new PolicyReviewError('invalid_policy_review_snapshot');
  }
  const candidates = await fetchAndValidateCandidates(input.fetchSource);

  emitPreview(input.writeOutput, existing, candidates);
  if (reviewedAt === undefined) {
    return existing === undefined
      ? { mode: 'preview', candidates }
      : { mode: 'preview', currentSnapshot: existing, candidates };
  }
  if (existing === undefined) {
    throw new PolicyReviewError('invalid_policy_review_snapshot');
  }
  const nextSnapshot = buildReviewedSnapshot(existing, candidates, reviewedAt);
  const serialized = `${JSON.stringify(nextSnapshot, null, 2)}\n`;
  let temporaryPath: string;
  try {
    temporaryPath = await input.fileSystem.writeTemporaryFile(REVIEWED_POLICY_SNAPSHOT_DIRECTORY, serialized);
  } catch {
    throw new PolicyReviewError('invalid_policy_review_filesystem');
  }
  if (!isSafeTemporaryPath(temporaryPath)) {
    throw new PolicyReviewError('invalid_policy_review_filesystem');
  }
  try {
    await input.fileSystem.renameTemporaryFile(temporaryPath, REVIEWED_POLICY_SNAPSHOT_PATH);
  } catch {
    throw new PolicyReviewError('invalid_policy_review_filesystem');
  }
  return { mode: 'write', snapshot: nextSnapshot };
}

async function readExistingSnapshot(
  fileSystem: PolicyReviewFileSystem
): Promise<Readonly<PolicySnapshot> | undefined> {
  let contents: string | undefined;
  try {
    contents = await fileSystem.readFile(REVIEWED_POLICY_SNAPSHOT_PATH);
  } catch {
    throw new PolicyReviewError('invalid_policy_review_snapshot');
  }
  if (contents === undefined) return undefined;

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(contents) as unknown;
  } catch {
    throw new PolicyReviewError('invalid_policy_review_snapshot');
  }
  const parsed = policySnapshotSchema.safeParse(parsedJson);
  if (!parsed.success || parsed.data.enforcementSha256 !== FIXED_POLICY_ENFORCEMENT_SHA256) {
    throw new PolicyReviewError('invalid_policy_review_snapshot');
  }
  try {
    return deepFreeze({ ...parsed.data, sources: parsed.data.sources.map((source) => ({ ...source })) });
  } catch {
    throw new PolicyReviewError('invalid_policy_review_snapshot');
  }
}

function parseReviewArguments(
  args: readonly string[],
  existing: Readonly<PolicySnapshot> | undefined
): string | undefined {
  if (args.length === 0) return undefined;
  if (args.length !== 3 || args[0] !== '--write' || args[1] !== '--reviewed-at') {
    throw new PolicyReviewError('invalid_policy_review_arguments');
  }
  const reviewedAt = args[2];
  if (reviewedAt === undefined || !isCanonicalIsoTimestamp(reviewedAt)) {
    throw new PolicyReviewError('invalid_policy_review_arguments');
  }
  if (existing !== undefined && reviewedAt !== existing.reviewedAt) {
    throw new PolicyReviewError('invalid_policy_review_arguments');
  }
  return reviewedAt;
}

type AvailablePolicySourceReviewResult = Extract<PolicySourceReviewResult, { state: 'available' }>;

async function fetchAndValidateCandidates(
  fetchSource: ReviewPolicyInput['fetchSource']
): Promise<readonly AvailablePolicySourceReviewResult[]> {
  const candidates: AvailablePolicySourceReviewResult[] = [];
  for (const source of POLICY_SOURCES) {
    let result: PolicySourceReviewResult;
    try {
      result = await fetchSource(source);
    } catch {
      throw new PolicyReviewError('invalid_policy_review_sources');
    }
    const validated = validateReviewResult(result, source.id, source.url);
    if (validated === undefined) {
      throw new PolicyReviewError('invalid_policy_review_sources');
    }
    candidates.push(validated);
  }
  return candidates;
}

function validateReviewResult(
  value: unknown,
  expectedSourceId: PolicySourceId,
  expectedUrl: PolicySourceUrl
): AvailablePolicySourceReviewResult | undefined {
  const record = readPlainDataRecord(value);
  if (record === undefined || record.state !== 'available') return undefined;
  const expectedKeys = ['canonicalContent', 'checkedAt', 'observedSha256', 'sourceId', 'state', 'url'];
  if (!hasExactKeys(record, expectedKeys)) return undefined;
  if (record.sourceId !== expectedSourceId || record.url !== expectedUrl) return undefined;
  if (typeof record.canonicalContent !== 'string' || !isSha256(record.observedSha256)) return undefined;
  if (!isPlainDate(record.checkedAt)) return undefined;
  const observedSha256 = createHash('sha256').update(record.canonicalContent, 'utf8').digest('hex');
  if (observedSha256 !== record.observedSha256) return undefined;
  return {
    state: 'available',
    sourceId: expectedSourceId,
    url: expectedUrl,
    checkedAt: record.checkedAt,
    observedSha256,
    canonicalContent: record.canonicalContent
  };
}

function buildReviewedSnapshot(
  existing: Readonly<PolicySnapshot>,
  candidates: readonly AvailablePolicySourceReviewResult[],
  reviewedAt: string
): Readonly<PolicySnapshot> {
  const next = {
    ...existing,
    reviewedAt,
    sources: candidates.map((candidate) => ({
      id: candidate.sourceId,
      url: candidate.url,
      retrievedAt: candidate.checkedAt.toISOString(),
      contentSha256: candidate.observedSha256
    }))
  };
  const parsed = policySnapshotSchema.safeParse(next);
  if (!parsed.success || parsed.data.enforcementSha256 !== FIXED_POLICY_ENFORCEMENT_SHA256) {
    throw new PolicyReviewError('invalid_policy_review_sources');
  }
  try {
    policyFingerprint(parsed.data);
  } catch {
    throw new PolicyReviewError('invalid_policy_review_sources');
  }
  return deepFreeze(parsed.data);
}

function emitPreview(
  writeOutput: (line: string) => void,
  existing: Readonly<PolicySnapshot> | undefined,
  candidates: readonly AvailablePolicySourceReviewResult[]
): void {
  for (const candidate of candidates) {
    const old = existing?.sources.find((source) => source.id === candidate.sourceId)?.contentSha256 ?? 'absent';
    writeOutput(`${candidate.sourceId} ${candidate.url} old: ${old} new: ${candidate.observedSha256}`);
  }
}

function isSafeTemporaryPath(path: string): boolean {
  if (typeof path !== 'string' || path.length === 0) return false;
  const resolved = resolve(path);
  return resolved !== REVIEWED_POLICY_SNAPSHOT_PATH && dirname(resolved) === REVIEWED_POLICY_SNAPSHOT_DIRECTORY;
}

function isCanonicalIsoTimestamp(value: string): boolean {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) && date.toISOString() === value;
}

function isPlainDate(value: unknown): value is Date {
  return value instanceof Date && Object.getPrototypeOf(value) === Date.prototype && Number.isFinite(value.getTime());
}

function isSha256(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/u.test(value);
}

function readPlainDataRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  try {
    if (Object.getPrototypeOf(value) !== Object.prototype || Object.getOwnPropertySymbols(value).length > 0) {
      return undefined;
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const output: Record<string, unknown> = {};
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (descriptor.enumerable !== true || !('value' in descriptor)) return undefined;
      output[key] = descriptor.value;
    }
    return output;
  } catch {
    return undefined;
  }
}

function hasExactKeys(record: Record<string, unknown>, expectedKeys: readonly string[]): boolean {
  const actual = Object.keys(record).sort();
  const expected = [...expectedKeys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

/** Injectable direct-execution seam; importing this module never invokes it. */
export async function runReviewPolicyCli(
  dependencies: ReviewPolicyCliDependencies,
  adapter: ReviewPolicyCliAdapter = { run: reviewPolicy }
): Promise<ReviewPolicyResult> {
  return adapter.run({
    args: dependencies.argv,
    fetchSource(source) {
      return reviewPolicyTransport({
        sourceId: source.id,
        url: source.url,
        dependencies: dependencies.sourceClientDependencies
      });
    },
    fileSystem: dependencies.fileSystem,
    writeOutput: dependencies.writeOutput
  });
}

/** Main guard seam: the real script will invoke this only when executed, never on import. */
export async function dispatchReviewPolicyMain(
  isMain: boolean,
  dependencies: ReviewPolicyCliDependencies,
  execute: (
    dependencies: ReviewPolicyCliDependencies
  ) => Promise<ReviewPolicyResult> = runReviewPolicyCli
): Promise<ReviewPolicyResult | undefined> {
  return isMain ? execute(dependencies) : undefined;
}

/** Separate guard predicate so the production CLI can call the same dispatcher under tsx. */
export function isReviewPolicyMain(entryPath: string | undefined, moduleUrl: string): boolean {
  if (entryPath === undefined) {
    return false;
  }
  return resolve(entryPath) === fileURLToPath(moduleUrl);
}

/**
 * The executable bottom-of-module guard delegates here with process.argv[1]
 * and import.meta.url. Keeping it injectable makes import-time execution impossible.
 */
export async function dispatchReviewPolicyModule(
  entryPath: string | undefined,
  moduleUrl: string,
  dependencies: ReviewPolicyCliDependencies,
  execute: (
    dependencies: ReviewPolicyCliDependencies
  ) => Promise<ReviewPolicyResult> = runReviewPolicyCli
): Promise<ReviewPolicyResult | undefined> {
  return dispatchReviewPolicyMain(isReviewPolicyMain(entryPath, moduleUrl), dependencies, execute);
}

/**
 * Exact executable path: normalized main guard, dependencies, then the shared
 * review dispatcher. RED deliberately supplies only a typed throwing factory.
 */
export async function dispatchReviewPolicyExecutable(
  entryPath: string | undefined,
  moduleUrl: string,
  createDependencies: () => ReviewPolicyCliDependencies,
  execute: (
    dependencies: ReviewPolicyCliDependencies
  ) => Promise<ReviewPolicyResult> = runReviewPolicyCli
): Promise<ReviewPolicyResult | undefined> {
  if (!isReviewPolicyMain(entryPath, moduleUrl)) {
    return undefined;
  }
  return execute(createDependencies());
}

export function createNodeReviewPolicyDependencies(): ReviewPolicyCliDependencies {
  return createNodeReviewPolicyCliDependencies({
    argv: globalThis.process.argv.slice(2),
    sourceClientDependencies: {
      fetch: async (url, options) => {
        const response = await globalThis.fetch(url, {
          redirect: options.redirect,
          credentials: options.credentials,
          headers: options.headers,
          signal: options.signal as globalThis.AbortSignal
        });
        return { status: response.status, text: () => response.text() };
      },
      now: () => new Date(),
      createAbortController: () => new globalThis.AbortController(),
      setTimeout: (callback, delayMs) => globalThis.setTimeout(callback, delayMs),
      clearTimeout: (timer) => globalThis.clearTimeout(timer as ReturnType<typeof globalThis.setTimeout>)
    },
    readFile: async (path) => {
      try {
        return await readFile(path, 'utf8');
      } catch (error) {
        if (isMissing(error)) return undefined;
        throw error;
      }
    },
    writeTemporaryFile: async (directory, contents) => {
      await mkdir(directory, { recursive: true, mode: 0o700 });
      const temporaryPath = join(directory, `.github-bug-bounty.v1.${randomUUID()}.tmp`);
      await writeFile(temporaryPath, contents, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
      await chmod(temporaryPath, 0o600);
      return temporaryPath;
    },
    renameTemporaryFile: async (temporaryPath, destination) => {
      const info = await lstat(temporaryPath);
      if (info.isSymbolicLink()) throw new Error('policy_review_symlink_rejected');
      await rename(temporaryPath, destination);
      await chmod(destination, 0o600);
    },
    writeOutput: (line) => { globalThis.process.stdout.write(`${line}\n`); }
  });
}

function isMissing(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT';
}

export function handleReviewPolicyMainFailure(
  error: unknown,
  writeError: (line: string) => void = (line) => process.stderr.write(line),
  setExitCode: (code: number) => void = (code) => { process.exitCode = code; }
): void {
  const code = error instanceof PolicyReviewError ? error.code : 'policy_review_failed';
  writeError(`review-policy: ${code}\n`);
  setExitCode(1);
}

if (isReviewPolicyMain(process.argv[1], import.meta.url)) {
  void dispatchReviewPolicyExecutable(
    process.argv[1],
    import.meta.url,
    createNodeReviewPolicyDependencies
  ).catch(handleReviewPolicyMainFailure);
}
