import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  FIXED_POLICY_ENFORCEMENT_SHA256,
  type PolicySnapshot
} from '@aegishub/bounty-core';

import {
  fetchPolicySourceForReview,
  POLICY_SOURCE_TIMEOUT_MS,
  POLICY_SOURCES,
  type FetchPolicySourceForReviewInput,
  type PolicySourceId
} from '../src/policy/source-client.js';
import {
  dispatchReviewPolicyMain,
  dispatchReviewPolicyModule,
  createNodeReviewPolicyCliDependencies,
  dispatchReviewPolicyExecutable,
  handleReviewPolicyMainFailure,
  isReviewPolicyMain,
  reviewPolicy,
  reviewPolicyTransport,
  runReviewPolicyCli,
  type PolicyReviewFileSystem,
  type PolicyReviewFetchResult
} from '../scripts/review-policy.js';
import {
  REVIEWED_POLICY_SNAPSHOT_DIRECTORY,
  REVIEWED_POLICY_SNAPSHOT_PATH
} from '../src/policy/snapshot.js';
import { bountyRuntimeRoot } from '../src/paths.js';

const reviewedAt = '2026-08-13T00:00:00.000Z';
const hash = (digit: string) => digit.repeat(64);

it('derives the only snapshot location from the package root, never cwd or caller input', () => {
  expect(REVIEWED_POLICY_SNAPSHOT_PATH).toBe(
    resolve(bountyRuntimeRoot, 'policy/github-bug-bounty.v1.json')
  );
});

function snapshot(overrides: Partial<PolicySnapshot> = {}): PolicySnapshot {
  return {
    schemaVersion: 1,
    policyVersion: 'github-bounty-2026-08-13.1',
    enforcementSha256: FIXED_POLICY_ENFORCEMENT_SHA256,
    sources: POLICY_SOURCES.map((source, index) => ({
      id: source.id,
      url: source.url,
      retrievedAt: reviewedAt,
      contentSha256: hash(String(index + 1))
    })),
    rulesOfEngagement: ['Keep fixed enforcement in code.'],
    inScopeTargets: ['api.github.com'],
    ineligibleCategories: ['No third-party content.'],
    severityReferences: ['https://example.test/severity'],
    reviewedAt,
    ...overrides
  };
}

function available(sourceId: PolicySourceId, index: number): PolicyReviewFetchResult {
  const source = POLICY_SOURCES[index];
  if (source === undefined) {
    throw new Error('test source index must be allowlisted');
  }
  const canonicalContent = `A reviewed\n\u0000canonical rule for ${sourceId}. `;
  return {
    state: 'available',
    sourceId,
    url: source.url,
    canonicalContent,
    observedSha256: rawCanonicalHash(canonicalContent),
    checkedAt: new Date('2026-08-13T12:00:00.000Z')
  };
}

function availableFor(sourceId: PolicySourceId): PolicyReviewFetchResult {
  return available(sourceId, POLICY_SOURCES.findIndex(({ id }) => id === sourceId));
}

function rawCanonicalHash(canonicalContent: string): string {
  return createHash('sha256').update(canonicalContent, 'utf8').digest('hex');
}

it('binds each available review digest to its canonical content', () => {
  const rules = available('rules', 0);
  const scope = available('scope', 1);
  expect(rules.observedSha256).toBe(rawCanonicalHash(rules.canonicalContent));
  expect(rules.observedSha256).not.toBe(scope.observedSha256);
});

function fakeFileSystem(contents: string | undefined, trace: string[]): PolicyReviewFileSystem {
  return {
    async readFile(path) {
      trace.push(`read:${path}`);
      return contents;
    },
    async writeTemporaryFile(directory, text) {
      trace.push(`write:${directory}:${text}`);
      return `${directory}/.github-bug-bounty.v1.json.tmp`;
    },
    async renameTemporaryFile(temp, destination) {
      trace.push(`rename:${temp}:${destination}`);
    }
  };
}

describe('review-policy RED contract', () => {
  it('previews exactly the five fixed sources, prints bounded canonical summaries and old/new hashes, and never writes on bootstrap', async () => {
    const fetched: Array<{ id: string; url: string }> = [];
    const output: string[] = [];
    const trace: string[] = [];

    await expect(
      reviewPolicy({
        args: [],
        async fetchSource(source) {
          fetched.push(source);
          return available(source.id, fetched.length - 1);
        },
        fileSystem: fakeFileSystem(undefined, trace),
        writeOutput(line) { output.push(line); }
      })
    ).resolves.toMatchObject({ mode: 'preview' });

    expect(fetched).toEqual(POLICY_SOURCES);
    expect(trace).toEqual([`read:${REVIEWED_POLICY_SNAPSHOT_PATH}`]);
    expect(output.join('\n')).toContain('old: absent');
    expect(output.join('\n')).toContain('new:');
    for (const [index, source] of POLICY_SOURCES.entries()) {
      expect(output.join('\n')).toContain(source.id);
      expect(output.join('\n')).toContain(source.url);
      expect(output.join('\n')).toContain(available(source.id, index).observedSha256);
    }
    expect(output.every((line) => line.length <= 320)).toBe(true);
    expect(output.every((line) => !line.includes('\n') && !line.includes('\u0000'))).toBe(true);
  });

  it('writes only under --write with one strict reviewed-at instant and preserves every non-retrieval snapshot field', async () => {
    const original = snapshot();
    const trace: string[] = [];
    await expect(
      reviewPolicy({
        args: ['--write', '--reviewed-at', reviewedAt],
        async fetchSource(source) {
          return available(source.id, POLICY_SOURCES.findIndex(({ id }) => id === source.id));
        },
        fileSystem: fakeFileSystem(JSON.stringify(original), trace),
        writeOutput() {}
      })
    ).resolves.toMatchObject({ mode: 'write' });

    const writePrefix = `write:${REVIEWED_POLICY_SNAPSHOT_DIRECTORY}:`;
    const write = trace.find((entry) => entry.startsWith(writePrefix));
    expect(write).toBeDefined();
    const written = JSON.parse(write!.slice(writePrefix.length)) as PolicySnapshot;
    expect({ ...written, sources: undefined }).toEqual({ ...original, sources: undefined });
    expect(written.sources.map(({ id, url, contentSha256, retrievedAt }) => ({ id, url, contentSha256, retrievedAt }))).toEqual(
      POLICY_SOURCES.map((source, index) => ({
        id: source.id,
        url: source.url,
        contentSha256: available(source.id, index).observedSha256,
        retrievedAt: '2026-08-13T12:00:00.000Z'
      }))
    );
    expect(trace.at(-1)).toBe(
      `rename:${REVIEWED_POLICY_SNAPSHOT_DIRECTORY}/.github-bug-bounty.v1.json.tmp:${REVIEWED_POLICY_SNAPSHOT_PATH}`
    );
  });

  it('previews an existing snapshot with its old and newly observed SHA-256 values without writing', async () => {
    const output: string[] = [];
    const trace: string[] = [];
    await expect(
      reviewPolicy({
        args: [],
        async fetchSource(source) {
          const index = POLICY_SOURCES.findIndex(({ id }) => id === source.id);
          const canonicalContent = `${available(source.id, index).canonicalContent} changed`;
          return {
            ...available(source.id, index),
            canonicalContent,
            observedSha256: rawCanonicalHash(canonicalContent)
          };
        },
        fileSystem: fakeFileSystem(JSON.stringify(snapshot()), trace),
        writeOutput(line) { output.push(line); }
      })
    ).resolves.toMatchObject({ mode: 'preview' });

    expect(output.join('\n')).toContain(hash('1'));
    expect(output.join('\n')).toContain(
      rawCanonicalHash(`${available('rules', 0).canonicalContent} changed`)
    );
    expect(trace.filter((entry) => entry.startsWith('write:') || entry.startsWith('rename:'))).toEqual([]);
  });

  it.each([
    ['malformed existing snapshot', '{'],
    ['existing enforcement-pin mismatch', JSON.stringify(snapshot({ enforcementSha256: hash('f') }))]
  ])('fails closed rather than treating %s as bootstrap absence', async (_caseName, contents) => {
    const output: string[] = [];
    const trace: string[] = [];
    await expect(
      reviewPolicy({
        args: [],
        async fetchSource(source) { return available(source.id, 0); },
        fileSystem: fakeFileSystem(contents, trace),
        writeOutput(line) { output.push(line); }
      })
    ).rejects.toMatchObject({ code: 'invalid_policy_review_snapshot' });
    expect(output.join('\n')).not.toContain('old: absent');
    expect(trace.filter((entry) => entry.startsWith('write:') || entry.startsWith('rename:'))).toEqual([]);
  });

  it.each([
    ['missing reviewed-at', ['--write'], JSON.stringify(snapshot()), 'invalid_policy_review_arguments'],
    ['non-ISO reviewed-at', ['--write', '--reviewed-at', 'tomorrow'], JSON.stringify(snapshot()), 'invalid_policy_review_arguments'],
    ['noncanonical reviewed-at', ['--write', '--reviewed-at', '2026-08-13T00:00:00Z'], JSON.stringify(snapshot()), 'invalid_policy_review_arguments'],
    ['unknown option', ['--write', '--reviewed-at', reviewedAt, '--force'], JSON.stringify(snapshot()), 'invalid_policy_review_arguments'],
    ['duplicate reviewed-at', ['--write', '--reviewed-at', reviewedAt, '--reviewed-at', reviewedAt], JSON.stringify(snapshot()), 'invalid_policy_review_arguments'],
    ['duplicate write', ['--write', '--write', '--reviewed-at', reviewedAt], JSON.stringify(snapshot()), 'invalid_policy_review_arguments'],
    ['extra positional argument', ['--write', '--reviewed-at', reviewedAt, 'extra'], JSON.stringify(snapshot()), 'invalid_policy_review_arguments'],
    ['reviewed-at without write', ['--reviewed-at', reviewedAt], JSON.stringify(snapshot()), 'invalid_policy_review_arguments'],
    ['reviewed-at does not equal top-level snapshot value', ['--write', '--reviewed-at', '2026-08-14T00:00:00.000Z'], JSON.stringify(snapshot()), 'invalid_policy_review_arguments'],
    ['missing snapshot', ['--write', '--reviewed-at', reviewedAt], undefined, 'invalid_policy_review_snapshot'],
    ['malformed snapshot', ['--write', '--reviewed-at', reviewedAt], '{', 'invalid_policy_review_snapshot'],
    ['unreviewed enforcement pin', ['--write', '--reviewed-at', reviewedAt], JSON.stringify(snapshot({ enforcementSha256: hash('f') })), 'invalid_policy_review_snapshot']
  ])('does not write when %s', async (_caseName, args, contents, code) => {
    const trace: string[] = [];
    await expect(
      reviewPolicy({
        args,
        async fetchSource(source) { return available(source.id, 0); },
        fileSystem: fakeFileSystem(contents, trace),
        writeOutput() {}
      })
    ).rejects.toMatchObject({ code });
    expect(trace.filter((entry) => entry.startsWith('write:') || entry.startsWith('rename:'))).toEqual([]);
  });

  it.each([
    ['unavailable source', (source: PolicySourceId): PolicyReviewFetchResult => ({ state: 'unavailable', sourceId: source, url: POLICY_SOURCES[0].url })],
    ['malformed source', (source: PolicySourceId): PolicyReviewFetchResult => ({ state: 'malformed', sourceId: source, url: POLICY_SOURCES[0].url, reason: 'missing-main' })],
    ['duplicate source result', (source: PolicySourceId): PolicyReviewFetchResult => available('rules', 0)],
    ['mismatched source URL', (source: PolicySourceId): PolicyReviewFetchResult => ({ ...available(source, 0), url: POLICY_SOURCES[1].url })]
  ])('refuses write without mutation for %s', async (_caseName, result) => {
    const trace: string[] = [];
    await expect(
      reviewPolicy({
        args: ['--write', '--reviewed-at', reviewedAt],
        async fetchSource(source) { return result(source.id); },
        fileSystem: fakeFileSystem(JSON.stringify(snapshot()), trace),
        writeOutput() {}
      })
    ).rejects.toMatchObject({ code: 'invalid_policy_review_sources' });
    expect(trace.filter((entry) => entry.startsWith('write:') || entry.startsWith('rename:'))).toEqual([]);
  });

  it('refuses a result whose observed hash does not match canonical content', async () => {
    const trace: string[] = [];
    await expect(
      reviewPolicy({
        args: ['--write', '--reviewed-at', reviewedAt],
        async fetchSource(source) {
          return { ...available(source.id, 0), observedSha256: hash('f') };
        },
        fileSystem: fakeFileSystem(JSON.stringify(snapshot()), trace),
        writeOutput() {}
      })
    ).rejects.toMatchObject({ code: 'invalid_policy_review_sources' });
    expect(trace.filter((entry) => entry.startsWith('write:') || entry.startsWith('rename:'))).toEqual([]);
  });

  it('refuses an outside-directory temporary file before rename', async () => {
    const trace: string[] = [];
    const fileSystem = fakeFileSystem(JSON.stringify(snapshot()), trace);
    fileSystem.writeTemporaryFile = async (_directory, text) => {
      trace.push(`write-outside:${text}`);
      return '/tmp/outside-policy-review.tmp';
    };
    await expect(
      reviewPolicy({
        args: ['--write', '--reviewed-at', reviewedAt],
        async fetchSource(source) { return availableFor(source.id); },
        fileSystem,
        writeOutput() {}
      })
    ).rejects.toMatchObject({ code: 'invalid_policy_review_filesystem' });
    expect(trace.some((entry) => entry.startsWith('write-outside:'))).toBe(true);
    expect(trace.some((entry) => entry.startsWith('rename:'))).toBe(false);
  });

  it.each([
    ['temporary write failure', (fileSystem: PolicyReviewFileSystem) => {
      fileSystem.writeTemporaryFile = async () => { throw new Error('write failed'); };
    }],
    ['rename failure', (fileSystem: PolicyReviewFileSystem) => {
      fileSystem.renameTemporaryFile = async () => { throw new Error('rename failed'); };
    }]
  ])('maps %s to a closed filesystem error without unsafe follow-up', async (_caseName, configure) => {
    const trace: string[] = [];
    const fileSystem = fakeFileSystem(JSON.stringify(snapshot()), trace);
    configure(fileSystem);
    await expect(
      reviewPolicy({
        args: ['--write', '--reviewed-at', reviewedAt],
        async fetchSource(source) { return availableFor(source.id); },
        fileSystem,
        writeOutput() {}
      })
    ).rejects.toMatchObject({ code: 'invalid_policy_review_filesystem' });
    if (_caseName === 'temporary write failure') {
      expect(trace.some((entry) => entry.startsWith('rename:'))).toBe(false);
    }
  });

  it('maps an injected fetchSource rejection to invalid review sources without writing', async () => {
    const trace: string[] = [];
    await expect(
      reviewPolicy({
        args: ['--write', '--reviewed-at', reviewedAt],
        async fetchSource() { throw new Error('transport rejected'); },
        fileSystem: fakeFileSystem(JSON.stringify(snapshot()), trace),
        writeOutput() {}
      })
    ).rejects.toMatchObject({ code: 'invalid_policy_review_sources' });
    expect(trace.filter((entry) => entry.startsWith('write:') || entry.startsWith('rename:'))).toEqual([]);
  });

  it.each([
    ['invalid checkedAt', { ...available('rules', 0), checkedAt: new Date('invalid') }],
    ['Date subclass checkedAt', { ...available('rules', 0), checkedAt: new (class extends Date {})(reviewedAt) }],
    ['wrong result source ID', { ...available('rules', 0), sourceId: 'scope' }],
    ['wrong result source URL', { ...available('rules', 0), url: POLICY_SOURCES[1].url }]
  ])('refuses a review result with %s before mutation', async (_caseName, result) => {
    const trace: string[] = [];
    await expect(
      reviewPolicy({
        args: ['--write', '--reviewed-at', reviewedAt],
        async fetchSource() { return result as PolicyReviewFetchResult; },
        fileSystem: fakeFileSystem(JSON.stringify(snapshot()), trace),
        writeOutput() {}
      })
    ).rejects.toMatchObject({ code: 'invalid_policy_review_sources' });
    expect(trace.filter((entry) => entry.startsWith('write:') || entry.startsWith('rename:'))).toEqual([]);
  });

  it('rejects hostile review result records before mutation without invoking getters', async () => {
    let getterCalls = 0;
    const accessorResult = {} as PolicyReviewFetchResult;
    Object.defineProperty(accessorResult, 'state', {
      enumerable: true,
      get() {
        getterCalls += 1;
        return 'available';
      }
    });
    const hiddenResult = Object.defineProperty({ ...available('rules', 0) }, 'hidden', { value: true }) as PolicyReviewFetchResult;
    const symbolResult = { ...available('rules', 0), [Symbol('hidden')]: true } as PolicyReviewFetchResult;
    const arrayResult = [available('rules', 0)] as unknown as PolicyReviewFetchResult;
    const subclassResult = new (class extends Array<PolicyReviewFetchResult> {})(available('rules', 0)) as unknown as PolicyReviewFetchResult;
    const reflectionThrowingResult = new Proxy({}, { ownKeys() { throw new Error('trap'); } }) as PolicyReviewFetchResult;

    for (const result of [accessorResult, hiddenResult, symbolResult, arrayResult, subclassResult, reflectionThrowingResult]) {
      const trace: string[] = [];
      await expect(
        reviewPolicy({
          args: ['--write', '--reviewed-at', reviewedAt],
          async fetchSource() { return result; },
          fileSystem: fakeFileSystem(JSON.stringify(snapshot()), trace),
          writeOutput() {}
        })
      ).rejects.toMatchObject({ code: 'invalid_policy_review_sources' });
      expect(trace.filter((entry) => entry.startsWith('write:') || entry.startsWith('rename:'))).toEqual([]);
    }
    expect(getterCalls).toBe(0);
  });

  it('has no import-time script side effects and binds direct execution to the shared review transport', async () => {
    const imported = await import('../scripts/review-policy.js');
    expect(imported).toHaveProperty('reviewPolicy');
    expect(imported.reviewPolicyTransport).toBe(reviewPolicyTransport);
  });

  it('constructs CLI review input from argv, the shared transport, and an injected atomic filesystem', async () => {
    const trace: string[] = [];
    const fileSystem = fakeFileSystem(undefined, trace);
    const cli = {
      argv: ['--write', '--reviewed-at', reviewedAt],
      sourceClientDependencies: {
        async fetch() { throw new Error('adapter must not fetch before review dispatch'); },
        now() { return new Date('2026-08-13T12:00:00.000Z'); },
        createAbortController() { return new globalThis.AbortController(); },
        setTimeout(callback: () => void, delay: number) { return globalThis.setTimeout(callback, delay); },
        clearTimeout(timer: unknown) { globalThis.clearTimeout(timer as ReturnType<typeof globalThis.setTimeout>); }
      },
      fileSystem,
      writeOutput() {}
    };
    let receivedArgs: readonly string[] | undefined;
    await expect(
      runReviewPolicyCli(cli, {
        async run(input) {
          receivedArgs = input.args;
          expect(input.fileSystem).toBe(fileSystem);
          expect(input.fetchSource).toBeTypeOf('function');
          return { mode: 'preview', candidates: [] };
        }
      })
    ).resolves.toEqual({ mode: 'preview', candidates: [] });
    expect(receivedArgs).toEqual(cli.argv);
    expect(trace).toEqual([]);
  });

  it('builds the concrete Node CLI adapter around the fixed absolute file and same-directory temp writer', () => {
    const trace: string[] = [];
    const fileSystem = fakeFileSystem(undefined, trace);
    const dependencies = createNodeReviewPolicyCliDependencies({
      argv: [],
      sourceClientDependencies: {
        async fetch() { throw new Error('not called'); },
        now() { return new Date('2026-08-13T12:00:00.000Z'); },
        createAbortController() { return new globalThis.AbortController(); },
        setTimeout(callback: () => void, delay: number) { return globalThis.setTimeout(callback, delay); },
        clearTimeout(timer: unknown) { globalThis.clearTimeout(timer as ReturnType<typeof globalThis.setTimeout>); }
      },
      ...fileSystem,
      writeOutput() {}
    });
    expect(dependencies.fileSystem.readFile).toBe(fileSystem.readFile);
    expect(dependencies.fileSystem.writeTemporaryFile).toBe(fileSystem.writeTemporaryFile);
    expect(dependencies.fileSystem.renameTemporaryFile).toBe(fileSystem.renameTemporaryFile);
    expect(trace).toEqual([]);
  });

  it('does not dispatch the executable main seam on import-style invocation', async () => {
    const cli = {
      argv: [],
      sourceClientDependencies: {
        async fetch() { throw new Error('not called'); },
        now() { return new Date('2026-08-13T12:00:00.000Z'); },
        createAbortController() { return new globalThis.AbortController(); },
        setTimeout(callback: () => void, delay: number) { return globalThis.setTimeout(callback, delay); },
        clearTimeout(timer: unknown) { globalThis.clearTimeout(timer as ReturnType<typeof globalThis.setTimeout>); }
      },
      fileSystem: fakeFileSystem(undefined, []),
      writeOutput() {}
    };
    let calls = 0;
    await expect(
      dispatchReviewPolicyMain(false, cli, async () => {
        calls += 1;
        return { mode: 'preview', candidates: [] };
      })
    ).resolves.toBeUndefined();
    expect(calls).toBe(0);
  });

  it('dispatches the main seam only with injected CLI dependencies', async () => {
    const cli = {
      argv: [],
      sourceClientDependencies: {
        async fetch() { throw new Error('not called'); },
        now() { return new Date('2026-08-13T12:00:00.000Z'); },
        createAbortController() { return new globalThis.AbortController(); },
        setTimeout(callback: () => void, delay: number) { return globalThis.setTimeout(callback, delay); },
        clearTimeout(timer: unknown) { globalThis.clearTimeout(timer as ReturnType<typeof globalThis.setTimeout>); }
      },
      fileSystem: fakeFileSystem(undefined, []),
      writeOutput() {}
    };
    await expect(
      dispatchReviewPolicyMain(true, cli, async (received) => {
        expect(received).toBe(cli);
        return { mode: 'preview', candidates: [] };
      })
    ).resolves.toEqual({ mode: 'preview', candidates: [] });
  });

  it('uses normalized argv/module identity for the executable-module dispatch guard', async () => {
    const modulePath = resolve('/tmp/review-policy.ts');
    const cli = {
      argv: [],
      sourceClientDependencies: {
        async fetch() { throw new Error('not called'); },
        now() { return new Date('2026-08-13T12:00:00.000Z'); },
        createAbortController() { return new globalThis.AbortController(); },
        setTimeout(callback: () => void, delay: number) { return globalThis.setTimeout(callback, delay); },
        clearTimeout(timer: unknown) { globalThis.clearTimeout(timer as ReturnType<typeof globalThis.setTimeout>); }
      },
      fileSystem: fakeFileSystem(undefined, []),
      writeOutput() {}
    };
    await expect(
      dispatchReviewPolicyModule('/tmp/../tmp/review-policy.ts', pathToFileURL(modulePath).href, cli, async () => ({
        mode: 'preview',
        candidates: []
      }))
    ).resolves.toEqual({ mode: 'preview', candidates: [] });
  });

  it('routes executable main through normalized guard, injected dependencies, and the shared dispatcher', async () => {
    const modulePath = resolve('/tmp/review-policy.ts');
    const trace: string[] = [];
    const runtime = {
      argv: [],
      sourceClientDependencies: {
        async fetch() { throw new Error('not called'); },
        now() { return new Date('2026-08-13T12:00:00.000Z'); },
        createAbortController() { return new globalThis.AbortController(); },
        setTimeout(callback: () => void, delay: number) { return globalThis.setTimeout(callback, delay); },
        clearTimeout(timer: unknown) { globalThis.clearTimeout(timer as ReturnType<typeof globalThis.setTimeout>); }
      },
      ...fakeFileSystem(undefined, trace),
      writeOutput() {}
    };
    await expect(
      dispatchReviewPolicyExecutable('/tmp/../tmp/review-policy.ts', pathToFileURL(modulePath).href, () =>
        createNodeReviewPolicyCliDependencies(runtime), async (dependencies) => {
        expect(dependencies.argv).toBe(runtime.argv);
        expect(dependencies.fileSystem.readFile).toBe(runtime.readFile);
        return { mode: 'preview', candidates: [] };
      })
    ).resolves.toEqual({ mode: 'preview', candidates: [] });
    expect(trace).toEqual([]);

    await expect(
      dispatchReviewPolicyExecutable('/tmp/review-policy.ts', pathToFileURL(modulePath).href, () =>
        createNodeReviewPolicyCliDependencies(runtime), async () => { throw new Error('review failed'); })
    ).rejects.toThrow('review failed');

    let created = 0;
    await expect(
      dispatchReviewPolicyExecutable('/tmp/other.ts', pathToFileURL(modulePath).href, () => {
          created += 1;
          return createNodeReviewPolicyCliDependencies(runtime);
        })
    ).resolves.toBeUndefined();
    expect(created).toBe(0);
  });

  it('handles executable RED failures through a sanitized output and exit-code seam', () => {
    const output: string[] = [];
    const codes: number[] = [];
    handleReviewPolicyMainFailure(
      new Error('sensitive detail'),
      (line) => { output.push(line); },
      (code) => { codes.push(code); }
    );
    expect(output).toEqual(['review-policy: policy_review_failed\n']);
    expect(codes).toEqual([1]);
  });

  it('defines a guarded executable-main entrypoint while preserving import-only no-op behavior', async () => {
    const imported = await import('../scripts/review-policy.js');
    expect(imported.dispatchReviewPolicyMain).toBeTypeOf('function');
    expect(imported.runReviewPolicyCli).toBeTypeOf('function');
    const modulePath = resolve('/tmp/review-policy.ts');
    expect(isReviewPolicyMain('/tmp/../tmp/review-policy.ts', pathToFileURL(modulePath).href)).toBe(true);
    expect(isReviewPolicyMain('/tmp/test.ts', pathToFileURL(modulePath).href)).toBe(false);
  });

  it('uses the dedicated review transport seam with the same fixed pair, manual redirect, omitted credentials, timeout, and one attempt', async () => {
    const source = POLICY_SOURCES[0];
    let attempts = 0;
    let timeoutMs = 0;
    const input: FetchPolicySourceForReviewInput = {
      sourceId: source.id,
      url: source.url,
      dependencies: {
        async fetch(url, options) {
          attempts += 1;
          expect(url).toBe(source.url);
          expect(options.redirect).toBe('manual');
          expect(options.credentials).toBe('omit');
          expect(options.headers).toEqual({});
          return { status: 200, async text() { return '<main>review body</main>'; } };
        },
        now() { return new Date('2026-08-13T12:00:00.000Z'); },
        createAbortController() { return new globalThis.AbortController(); },
        setTimeout(callback, delay) {
          timeoutMs = delay;
          return globalThis.setTimeout(callback, delay);
        },
        clearTimeout(timer) { globalThis.clearTimeout(timer as ReturnType<typeof globalThis.setTimeout>); }
      }
    };

    await expect(fetchPolicySourceForReview(input)).resolves.toMatchObject({
      state: 'available',
      sourceId: source.id,
      url: source.url,
      canonicalContent: 'review body',
      observedSha256: rawCanonicalHash('review body')
    });
    expect(attempts).toBe(1);
    expect(timeoutMs).toBe(POLICY_SOURCE_TIMEOUT_MS);
  });
});
