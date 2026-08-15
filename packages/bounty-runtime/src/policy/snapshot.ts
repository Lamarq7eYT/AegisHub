import { dirname, resolve } from 'node:path';

import {
  FIXED_POLICY_ENFORCEMENT_SHA256,
  policyFingerprint,
  policyStatusSchema,
  policySnapshotSchema,
  type PolicySnapshot,
  type PolicyStatus
} from '@aegishub/bounty-core';
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

const EXPECTED_SOURCES = [
  ['rules', 'https://bounty.github.com/rules.html'],
  ['scope', 'https://bounty.github.com/scope.html'],
  ['targets', 'https://bounty.github.com/targets.html'],
  ['ineligible', 'https://bounty.github.com/ineligible.html'],
  ['rewards', 'https://bounty.github.com/rewards.html']
] as const;

export async function loadReviewedPolicySnapshot(input: {
  readonly fileSystem: ReviewedPolicySnapshotFileSystem;
}): Promise<LoadedReviewedPolicySnapshot> {
  let contents: string;
  try {
    contents = await input.fileSystem.readFile(REVIEWED_POLICY_SNAPSHOT_PATH);
  } catch {
    throw new PolicySnapshotError('invalid_policy_snapshot');
  }

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(contents) as unknown;
  } catch {
    throw new PolicySnapshotError('invalid_policy_snapshot');
  }

  const parsed = policySnapshotSchema.safeParse(parsedJson);
  if (!parsed.success || !hasExpectedSources(parsed.data)) {
    throw new PolicySnapshotError('invalid_policy_snapshot');
  }
  if (parsed.data.enforcementSha256 !== FIXED_POLICY_ENFORCEMENT_SHA256) {
    throw new PolicySnapshotError('policy_enforcement_mismatch');
  }

  const snapshot = deepFreeze(parsed.data);
  try {
    return { snapshot, fingerprint: policyFingerprint(snapshot) };
  } catch {
    throw new PolicySnapshotError('invalid_policy_snapshot');
  }
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

export class PolicyMonitor {
  readonly #dependencies: PolicyMonitorDependencies;
  #plannedSnapshot: Readonly<PolicySnapshot> | undefined;
  #plannedFingerprint: string | undefined;
  #freshness: Readonly<PolicyStatus> | undefined;

  constructor(dependencies: PolicyMonitorDependencies) {
    this.#dependencies = dependencies;
  }

  async plan(): Promise<string> {
    const loaded = await loadReviewedPolicySnapshot(this.#dependencies);
    this.#plannedSnapshot = loaded.snapshot;
    this.#plannedFingerprint = loaded.fingerprint;
    this.#freshness = undefined;
    return loaded.fingerprint;
  }

  async checkFreshnessBeforeExecution(): Promise<Readonly<PolicyStatus>> {
    if (this.#plannedSnapshot === undefined || this.#plannedFingerprint === undefined) {
      throw new PolicyMonitorError('policy_freshness_not_checked');
    }
    if (this.#freshness !== undefined) return this.#freshness;

    await this.#assertLocalSnapshotUnchanged();
    let remoteStatus: PolicyStatus;
    try {
      remoteStatus = await this.#dependencies.checkRemoteFreshness(this.#plannedSnapshot);
    } catch {
      throw new PolicyMonitorError('invalid_policy_remote_status');
    }
    const validated = validateRemoteStatus(remoteStatus, this.#plannedSnapshot.policyVersion);
    if (validated === undefined) {
      throw new PolicyMonitorError('invalid_policy_remote_status');
    }
    this.#freshness = deepFreeze(validated);
    return this.#freshness;
  }

  async beforeOperation(): Promise<void> {
    if (this.#freshness === undefined) {
      throw new PolicyMonitorError('policy_freshness_not_checked');
    }
    await this.#assertLocalSnapshotUnchanged();
  }

  async #assertLocalSnapshotUnchanged(): Promise<void> {
    if (this.#plannedFingerprint === undefined) {
      throw new PolicyMonitorError('policy_freshness_not_checked');
    }
    let current: LoadedReviewedPolicySnapshot;
    try {
      current = await loadReviewedPolicySnapshot(this.#dependencies);
    } catch {
      throw new PolicyMonitorError('policy_changed_during_run');
    }
    if (current.fingerprint !== this.#plannedFingerprint) {
      throw new PolicyMonitorError('policy_changed_during_run');
    }
  }
}

function hasExpectedSources(snapshot: PolicySnapshot): boolean {
  if (snapshot.sources.length !== EXPECTED_SOURCES.length) return false;
  const seen = new Set<string>();
  for (const source of snapshot.sources) {
    if (seen.has(source.id)) return false;
    seen.add(source.id);
  }
  return EXPECTED_SOURCES.every(([id, url]) => snapshot.sources.some((source) => source.id === id && source.url === url));
}

function validateRemoteStatus(value: unknown, policyVersion: string): PolicyStatus | undefined {
  const safeValue = cloneDataWithoutAccessors(value);
  if (safeValue === undefined) return undefined;
  const parsed = policyStatusSchema.safeParse(safeValue);
  if (!parsed.success || parsed.data.policyVersion !== policyVersion || !hasExpectedStatusSources(parsed.data)) {
    return undefined;
  }
  return parsed.data;
}

function hasExpectedStatusSources(status: PolicyStatus): boolean {
  if (status.sourceStatuses.length !== EXPECTED_SOURCES.length) return false;
  const seen = new Set<string>();
  for (const sourceStatus of status.sourceStatuses) {
    if (seen.has(sourceStatus.sourceId)) return false;
    seen.add(sourceStatus.sourceId);
  }
  return EXPECTED_SOURCES.every(([id]) => status.sourceStatuses.some((sourceStatus) => sourceStatus.sourceId === id));
}

function cloneDataWithoutAccessors(value: unknown): unknown | undefined {
  try {
    if (value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      return value;
    }
    if (typeof value !== 'object') return undefined;

    const prototype = Object.getPrototypeOf(value);
    if (Array.isArray(value)) {
      if (prototype !== Array.prototype) return undefined;
      const ownNames = Object.getOwnPropertyNames(value);
      if (ownNames.length !== value.length + 1 || ownNames.at(-1) !== 'length') return undefined;
      const output: unknown[] = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (descriptor?.enumerable !== true || !('value' in descriptor)) return undefined;
        const child = cloneDataWithoutAccessors(descriptor.value);
        if (child === undefined && descriptor.value !== undefined) return undefined;
        output.push(child);
      }
      return output;
    }
    if (prototype !== Object.prototype || Object.getOwnPropertySymbols(value).length > 0) return undefined;

    const descriptors = Object.getOwnPropertyDescriptors(value);
    const output: Record<string, unknown> = {};
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (descriptor.enumerable !== true || !('value' in descriptor)) return undefined;
      const child = cloneDataWithoutAccessors(descriptor.value);
      if (child === undefined && descriptor.value !== undefined) return undefined;
      output[key] = child;
    }
    return output;
  } catch {
    return undefined;
  }
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
