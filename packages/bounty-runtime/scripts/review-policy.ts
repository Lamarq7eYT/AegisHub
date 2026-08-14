import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { PolicySnapshot } from '@aegishub/bounty-core';

import type {
  FetchPolicySourceForReviewInput,
  PolicySourceClientDependencies,
  PolicySourceId,
  PolicySourceReviewResult,
  PolicySourceUrl
} from '../src/policy/source-client.js';
import { fetchPolicySourceForReview } from '../src/policy/source-client.js';
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

/** API-only RED seam. It must remain side-effect free until the GREEN cycle. */
export async function reviewPolicy(_input: ReviewPolicyInput): Promise<ReviewPolicyResult> {
  throw new PolicyReviewError('unimplemented_policy_review');
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

export function createUnimplementedNodeDependencies(): ReviewPolicyCliDependencies {
  throw new PolicyReviewError('unimplemented_policy_review');
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
    createUnimplementedNodeDependencies
  ).catch(handleReviewPolicyMainFailure);
}
