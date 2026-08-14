import { dirname, resolve } from 'node:path';

import type { PolicySnapshot, PolicyStatus } from '@aegishub/bounty-core';
import { bountyRuntimeRoot } from '../paths.js';

/** Fixed from this package's module location; it never derives from cwd or caller input. */
export const REVIEWED_POLICY_SNAPSHOT_PATH = resolve(bountyRuntimeRoot, 'policy/github-bug-bounty.v1.json');
export const REVIEWED_POLICY_SNAPSHOT_DIRECTORY = dirname(REVIEWED_POLICY_SNAPSHOT_PATH);

export interface ReviewedPolicySnapshotFileSystem {
  readFile(path: typeof REVIEWED_POLICY_SNAPSHOT_PATH): Promise<string>;
}

export interface LoadedReviewedPolicySnapshot {
  readonly snapshot: Readonly<PolicySnapshot>;
  readonly fingerprint: string;
}

export type PolicySnapshotErrorCode =
  | 'unimplemented_policy_snapshot'
  | 'invalid_policy_snapshot'
  | 'policy_enforcement_mismatch';

export class PolicySnapshotError extends Error {
  constructor(readonly code: PolicySnapshotErrorCode) {
    super(code);
    this.name = 'PolicySnapshotError';
  }
}

export async function loadReviewedPolicySnapshot(_input: {
  readonly fileSystem: ReviewedPolicySnapshotFileSystem;
}): Promise<LoadedReviewedPolicySnapshot> {
  throw new PolicySnapshotError('unimplemented_policy_snapshot');
}

export type PolicyMonitorErrorCode =
  | 'unimplemented_policy_monitor'
  | 'policy_changed_during_run'
  | 'policy_freshness_not_checked'
  | 'invalid_policy_remote_status';

export class PolicyMonitorError extends Error {
  constructor(readonly code: PolicyMonitorErrorCode) {
    super(code);
    this.name = 'PolicyMonitorError';
  }
}

export interface PolicyMonitorDependencies {
  readonly fileSystem: ReviewedPolicySnapshotFileSystem;
  readonly checkRemoteFreshness: (snapshot: Readonly<PolicySnapshot>) => Promise<PolicyStatus>;
}

/** API-only RED seam. Its methods deliberately contain no monitoring behavior. */
export class PolicyMonitor {
  constructor(_dependencies: PolicyMonitorDependencies) {}

  async plan(): Promise<string> {
    throw new PolicyMonitorError('unimplemented_policy_monitor');
  }

  async checkFreshnessBeforeExecution(): Promise<Readonly<PolicyStatus>> {
    throw new PolicyMonitorError('unimplemented_policy_monitor');
  }

  async beforeOperation(): Promise<void> {
    throw new PolicyMonitorError('unimplemented_policy_monitor');
  }
}
