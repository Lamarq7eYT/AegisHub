import { describe, expect, it } from 'vitest';
import {
  FIXED_POLICY_ENFORCEMENT_SHA256,
  policyFingerprint,
  type PolicySnapshot,
  type PolicyStatus
} from '@aegishub/bounty-core';

import {
  loadReviewedPolicySnapshot,
  PolicyMonitor,
  REVIEWED_POLICY_SNAPSHOT_PATH,
  type ReviewedPolicySnapshotFileSystem
} from '../src/policy/snapshot.js';

const now = new Date('2026-08-13T12:00:00.000Z');
const hash = (digit: string) => digit.repeat(64);

function reviewedSnapshot(overrides: Partial<PolicySnapshot> = {}): PolicySnapshot {
  return {
    schemaVersion: 1,
    policyVersion: 'github-bounty-2026-08-13.1',
    enforcementSha256: FIXED_POLICY_ENFORCEMENT_SHA256,
    sources: [
      { id: 'rules', url: 'https://bounty.github.com/rules.html', retrievedAt: now.toISOString(), contentSha256: hash('1') },
      { id: 'scope', url: 'https://bounty.github.com/scope.html', retrievedAt: now.toISOString(), contentSha256: hash('2') },
      { id: 'targets', url: 'https://bounty.github.com/targets.html', retrievedAt: now.toISOString(), contentSha256: hash('3') },
      { id: 'ineligible', url: 'https://bounty.github.com/ineligible.html', retrievedAt: now.toISOString(), contentSha256: hash('4') },
      { id: 'rewards', url: 'https://bounty.github.com/rewards.html', retrievedAt: now.toISOString(), contentSha256: hash('5') }
    ],
    rulesOfEngagement: ['Read the current policy.'],
    inScopeTargets: ['api.github.com'],
    ineligibleCategories: ['No third-party access.'],
    severityReferences: [],
    reviewedAt: now.toISOString(),
    ...overrides
  };
}

function readOnlyFileSystem(contents: string, reads: string[]): ReviewedPolicySnapshotFileSystem {
  return {
    async readFile(path) {
      reads.push(path);
      return contents;
    }
  };
}

const currentStatus: PolicyStatus = {
  schemaVersion: 1,
  policyVersion: 'github-bounty-2026-08-13.1',
  state: 'current',
  checkedAt: now.toISOString(),
  sourceStatuses: [
    { sourceId: 'rules', state: 'match', checkedAt: now.toISOString(), observedSha256: hash('1') },
    { sourceId: 'scope', state: 'match', checkedAt: now.toISOString(), observedSha256: hash('2') },
    { sourceId: 'targets', state: 'match', checkedAt: now.toISOString(), observedSha256: hash('3') },
    { sourceId: 'ineligible', state: 'match', checkedAt: now.toISOString(), observedSha256: hash('4') },
    { sourceId: 'rewards', state: 'match', checkedAt: now.toISOString(), observedSha256: hash('5') }
  ]
};

describe('reviewed policy snapshot loader RED contract', () => {
  it('uses only the code-owned snapshot path and returns a deep-frozen snapshot with its stable fingerprint', async () => {
    const snapshot = reviewedSnapshot();
    const reads: string[] = [];

    await expect(
      loadReviewedPolicySnapshot({ fileSystem: readOnlyFileSystem(JSON.stringify(snapshot), reads) })
    ).resolves.toMatchObject({ snapshot, fingerprint: policyFingerprint(snapshot) });
    expect(reads).toEqual([REVIEWED_POLICY_SNAPSHOT_PATH]);

    const loaded = await loadReviewedPolicySnapshot({
      fileSystem: readOnlyFileSystem(JSON.stringify(snapshot), [])
    });
    expect(Object.isFrozen(loaded.snapshot)).toBe(true);
    expect(Object.isFrozen(loaded.snapshot.sources)).toBe(true);
    expect(Object.isFrozen(loaded.snapshot.sources[0])).toBe(true);
    expect(Object.isFrozen(loaded.snapshot.rulesOfEngagement)).toBe(true);
    expect(Object.isFrozen(loaded.snapshot.inScopeTargets)).toBe(true);
    expect(Object.isFrozen(loaded.snapshot.ineligibleCategories)).toBe(true);
    expect(Object.isFrozen(loaded.snapshot.severityReferences)).toBe(true);
  });

  it.each([
    ['malformed JSON', '{', 'invalid_policy_snapshot'],
    ['strict-schema extra key', JSON.stringify({ ...reviewedSnapshot(), unexpected: true }), 'invalid_policy_snapshot'],
    ['five-source duplicate identity', JSON.stringify(reviewedSnapshot({ sources: [...reviewedSnapshot().sources.slice(0, 4), reviewedSnapshot().sources[0]] })), 'invalid_policy_snapshot'],
    ['five-source unknown identity', JSON.stringify(reviewedSnapshot({ sources: [...reviewedSnapshot().sources.slice(0, 4), { ...reviewedSnapshot().sources[4], id: 'unknown' }] })), 'invalid_policy_snapshot'],
    ['wrong URL with all five sources', JSON.stringify(reviewedSnapshot({ sources: [{ ...reviewedSnapshot().sources[0], url: 'https://example.test/rules' }, ...reviewedSnapshot().sources.slice(1)] })), 'invalid_policy_snapshot'],
    ['unreviewed enforcement pin', JSON.stringify(reviewedSnapshot({ enforcementSha256: hash('f') })), 'policy_enforcement_mismatch']
  ])('rejects %s with a typed closed error before use', async (_caseName, contents, code) => {
    await expect(
      loadReviewedPolicySnapshot({ fileSystem: readOnlyFileSystem(contents, []) })
    ).rejects.toMatchObject({ code });
  });

  it('maps a fixed-path read failure to the typed snapshot error', async () => {
    await expect(
      loadReviewedPolicySnapshot({
        fileSystem: {
          async readFile() {
            throw new Error('unavailable local file');
          }
        }
      })
    ).rejects.toMatchObject({ code: 'invalid_policy_snapshot' });
  });
});

describe('PolicyMonitor RED contract', () => {
  it('stores the planning fingerprint, rereads locally before freshness and each operation, and caches one frozen remote status', async () => {
    const snapshot = reviewedSnapshot();
    const reads: string[] = [];
    const monitor = new PolicyMonitor({
      fileSystem: readOnlyFileSystem(JSON.stringify(snapshot), reads),
      async checkRemoteFreshness() {
        return currentStatus;
      }
    });

    await expect(monitor.plan()).resolves.toBe(policyFingerprint(snapshot));
    const first = await monitor.checkFreshnessBeforeExecution();
    const second = await monitor.checkFreshnessBeforeExecution();
    expect(first).toEqual(currentStatus);
    expect(second).toBe(first);
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.sourceStatuses)).toBe(true);
    expect(first.sourceStatuses.every((status) => Object.isFrozen(status))).toBe(true);
    await expect(monitor.beforeOperation()).resolves.toBeUndefined();
    await expect(monitor.beforeOperation()).resolves.toBeUndefined();
    expect(reads).toEqual([
      REVIEWED_POLICY_SNAPSHOT_PATH,
      REVIEWED_POLICY_SNAPSHOT_PATH,
      REVIEWED_POLICY_SNAPSHOT_PATH,
      REVIEWED_POLICY_SNAPSHOT_PATH
    ]);
  });

  it('stops with policy_changed_during_run before remote freshness when the local snapshot changes', async () => {
    const planned = JSON.stringify(reviewedSnapshot());
    const cases: Array<readonly [string, () => Promise<string>]> = [
      ['changed content', async () => JSON.stringify(reviewedSnapshot({ policyVersion: 'changed' }))],
      ['malformed JSON', async () => '{'],
      ['read failure', async () => { throw new Error('read failure'); }]
    ];

    for (const [_caseName, secondRead] of cases) {
      let reads = 0;
      let remoteCalls = 0;
      const monitor = new PolicyMonitor({
        fileSystem: {
          async readFile() {
            reads += 1;
            return reads === 1 ? planned : secondRead();
          }
        },
        async checkRemoteFreshness() {
          remoteCalls += 1;
          return currentStatus;
        }
      });
      await expect(monitor.plan()).resolves.toBe(policyFingerprint(JSON.parse(planned) as PolicySnapshot));
      await expect(monitor.checkFreshnessBeforeExecution()).rejects.toMatchObject({
        code: 'policy_changed_during_run'
      });
      expect(remoteCalls).toBe(0);
    }
  });

  it('stops each operation after valid freshness when the next local read changes, malforms, or fails', async () => {
    const planned = JSON.stringify(reviewedSnapshot());
    const cases: Array<readonly [string, () => Promise<string>]> = [
      ['changed content', async () => JSON.stringify(reviewedSnapshot({ policyVersion: 'changed' }))],
      ['malformed JSON', async () => '{'],
      ['read failure', async () => { throw new Error('read failure'); }]
    ];
    for (const [_caseName, thirdRead] of cases) {
      let reads = 0;
      const monitor = new PolicyMonitor({
        fileSystem: {
          async readFile() {
            reads += 1;
            return reads <= 2 ? planned : thirdRead();
          }
        },
        async checkRemoteFreshness() { return currentStatus; }
      });
      await expect(monitor.plan()).resolves.toBeTypeOf('string');
      await expect(monitor.checkFreshnessBeforeExecution()).resolves.toEqual(currentStatus);
      await expect(monitor.beforeOperation()).rejects.toMatchObject({
        code: 'policy_changed_during_run'
      });
    }
  });

  it('requires one remote freshness check immediately before execution and caches it across operations', async () => {
    let remoteChecks = 0;
    let receivedSnapshot: Readonly<PolicySnapshot> | undefined;
    const plannedSnapshot = reviewedSnapshot();
    const monitor = new PolicyMonitor({
      fileSystem: readOnlyFileSystem(JSON.stringify(plannedSnapshot), []),
      async checkRemoteFreshness(snapshot) {
        remoteChecks += 1;
        receivedSnapshot = snapshot;
        return currentStatus;
      }
    });

    await expect(monitor.beforeOperation()).rejects.toMatchObject({
      code: 'policy_freshness_not_checked'
    });
    await expect(monitor.checkFreshnessBeforeExecution()).rejects.toMatchObject({
      code: 'policy_freshness_not_checked'
    });
    expect(remoteChecks).toBe(0);
    await expect(monitor.plan()).resolves.toBeTypeOf('string');
    const first = await monitor.checkFreshnessBeforeExecution();
    const second = await monitor.checkFreshnessBeforeExecution();
    expect(first).toBe(second);
    expect(first).toEqual(currentStatus);
    await expect(monitor.beforeOperation()).resolves.toBeUndefined();
    expect(remoteChecks).toBe(1);
    expect(receivedSnapshot).toEqual(plannedSnapshot);
    expect(Object.isFrozen(receivedSnapshot)).toBe(true);
  });

  it.each([
    ['wrong policy version', { ...currentStatus, policyVersion: 'other-policy' }],
    ['duplicate source identity', { ...currentStatus, sourceStatuses: [currentStatus.sourceStatuses[0], currentStatus.sourceStatuses[0], ...currentStatus.sourceStatuses.slice(2)] }],
    ['unknown source identity', { ...currentStatus, sourceStatuses: [{ ...currentStatus.sourceStatuses[0], sourceId: 'unknown' }, ...currentStatus.sourceStatuses.slice(1)] }],
    ['missing source identity', { ...currentStatus, sourceStatuses: currentStatus.sourceStatuses.slice(0, 4) }],
    ['sparse source statuses', (() => { const statuses = [...currentStatus.sourceStatuses]; delete statuses[2]; return { ...currentStatus, sourceStatuses: statuses }; })()],
    ['Array subclass source statuses', { ...currentStatus, sourceStatuses: new (class extends Array<typeof currentStatus.sourceStatuses[number]> {})(...currentStatus.sourceStatuses) }],
    ['extra source-status array property', (() => { const statuses = [...currentStatus.sourceStatuses] as typeof currentStatus.sourceStatuses & { extra?: boolean }; statuses.extra = true; return { ...currentStatus, sourceStatuses: statuses }; })()],
    ['missing required status field', { schemaVersion: 1 }]
  ])('rejects invalid remote freshness status (%s) without caching it', async (_caseName, remoteStatus) => {
    let remoteCalls = 0;
    const monitor = new PolicyMonitor({
      fileSystem: readOnlyFileSystem(JSON.stringify(reviewedSnapshot()), []),
      async checkRemoteFreshness() {
        remoteCalls += 1;
        return remoteStatus as PolicyStatus;
      }
    });
    await expect(monitor.plan()).resolves.toBeTypeOf('string');
    await expect(monitor.checkFreshnessBeforeExecution()).rejects.toMatchObject({
      code: 'invalid_policy_remote_status'
    });
    await expect(monitor.checkFreshnessBeforeExecution()).rejects.toMatchObject({
      code: 'invalid_policy_remote_status'
    });
    expect(remoteCalls).toBe(2);
  });

  it('rejects accessor, symbol, hidden-property, non-plain, and reflection-throwing remote status values without invoking getters', async () => {
    let getterCalls = 0;
    const accessorStatus = {} as PolicyStatus;
    Object.defineProperty(accessorStatus, 'policyVersion', {
      enumerable: true,
      get() {
        getterCalls += 1;
        return currentStatus.policyVersion;
      }
    });
    const symbolStatus = { ...currentStatus, [Symbol('hidden')]: true } as PolicyStatus;
    const hiddenStatus = Object.defineProperty({ ...currentStatus }, 'hidden', { value: true }) as PolicyStatus;
    const nonPlainStatus = Object.create(currentStatus) as PolicyStatus;
    const reflectionThrowingStatus = new Proxy({}, { ownKeys() { throw new Error('trap'); } }) as PolicyStatus;

    for (const remoteStatus of [accessorStatus, symbolStatus, hiddenStatus, nonPlainStatus, reflectionThrowingStatus]) {
      const monitor = new PolicyMonitor({
        fileSystem: readOnlyFileSystem(JSON.stringify(reviewedSnapshot()), []),
        async checkRemoteFreshness() { return remoteStatus; }
      });
      await expect(monitor.plan()).resolves.toBeTypeOf('string');
      await expect(monitor.checkFreshnessBeforeExecution()).rejects.toMatchObject({
        code: 'invalid_policy_remote_status'
      });
    }
    expect(getterCalls).toBe(0);
  });

  it('rejects hostile individual source-status records without invoking getters', async () => {
    let getterCalls = 0;
    const accessor = {} as PolicyStatus['sourceStatuses'][number];
    Object.defineProperty(accessor, 'sourceId', {
      enumerable: true,
      get() {
        getterCalls += 1;
        return 'rules';
      }
    });
    const symbol = { ...currentStatus.sourceStatuses[0], [Symbol('hidden')]: true };
    const hidden = Object.defineProperty({ ...currentStatus.sourceStatuses[0] }, 'hidden', { value: true });
    const nonPlain = Object.create(currentStatus.sourceStatuses[0]);
    const reflectionThrowing = new Proxy({}, { getOwnPropertyDescriptor() { throw new Error('trap'); } });

    for (const sourceStatus of [accessor, symbol, hidden, nonPlain, reflectionThrowing]) {
      const monitor = new PolicyMonitor({
        fileSystem: readOnlyFileSystem(JSON.stringify(reviewedSnapshot()), []),
        async checkRemoteFreshness() {
          return {
            ...currentStatus,
            sourceStatuses: [sourceStatus, ...currentStatus.sourceStatuses.slice(1)]
          } as PolicyStatus;
        }
      });
      await expect(monitor.plan()).resolves.toBeTypeOf('string');
      await expect(monitor.checkFreshnessBeforeExecution()).rejects.toMatchObject({
        code: 'invalid_policy_remote_status'
      });
    }
    expect(getterCalls).toBe(0);
  });
});
