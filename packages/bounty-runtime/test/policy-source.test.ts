import { describe, expect, it } from 'vitest';
import {
  canonicalizePolicyHtml,
  fetchPolicySource,
  hashCanonicalPolicyHtml,
  MAX_POLICY_SOURCE_BODY_BYTES,
  POLICY_SOURCE_TIMEOUT_MS,
  POLICY_SOURCES,
  POLICY_SOURCE_URLS,
  PolicySourceContentError,
  PolicySourceInputError,
  type PolicyFetch,
  type PolicySourceClientDependencies,
  type PolicySourceId,
  type PolicySourceUrl
} from '../src/policy/source-client.js';
import {
  computePolicyStatus,
  FIXED_POLICY_ENFORCEMENT_SHA256,
  type PolicySnapshot
} from '@aegishub/bounty-core';

const now = new Date('2026-08-13T12:00:00.000Z');
const expectedSha256 = 'c779d858bb6f7d2b31a19231b7fb8d0cd8f286e5dd9f48a37baeb1b612dd8af1';
const sourceIds = ['rules', 'scope', 'targets', 'ineligible', 'rewards'] as const;

const semanticHtml = `
  <html><body>
    <nav>volatile navigation</nav>
    <main class="policy-shell" data-revision="1">
      <p>Keep requests low.</p>
      <p>Caf&eacute; &amp; tea.</p>
    </main>
    <footer>volatile footer</footer>
  </body></html>
`;

const equivalentHtml = `
  <html><body>
    <nav data-ui="new">different navigation</nav><script>ignored()</script><style>.ignored{}</style>
    <main id="reviewed-policy">
      <p>  Keep\trequests low. </p>

      <p>Cafe\u0301 & tea.</p>
    </main>
    <footer>different footer</footer>
  </body></html>
`;

const entityAndNfcHtml = `
  <main><p>&amp; &lt; &gt; &quot; &apos; &nbsp; Caf&eacute;</p></main>
`;
const entityAndNfcEquivalentHtml = `
  <main><p>&#38; &#60; &#62; &#34; &#39; &#160; Cafe\u0301</p></main>
`;

function contentErrorCode(run: () => unknown, code: PolicySourceContentError['code']): void {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(PolicySourceContentError);
    expect((error as PolicySourceContentError).code).toBe(code);
    return;
  }

  throw new Error(`Expected PolicySourceContentError with code ${code}`);
}

async function inputErrorCode(
  run: () => Promise<unknown>,
  code: PolicySourceInputError['code']
): Promise<void> {
  try {
    await run();
  } catch (error) {
    expect(error).toBeInstanceOf(PolicySourceInputError);
    expect((error as PolicySourceInputError).code).toBe(code);
    return;
  }

  throw new Error(`Expected PolicySourceInputError with code ${code}`);
}

function dependencies(fetch: PolicyFetch): PolicySourceClientDependencies {
  return {
    fetch,
    now: () => now,
    createAbortController: () => new AbortController(),
    setTimeout: () => ({ kind: 'timer' }),
    clearTimeout: () => undefined
  };
}

function reviewedSnapshot(): PolicySnapshot {
  return {
    schemaVersion: 1,
    policyVersion: 'github-bounty-2026-08-13.1',
    enforcementSha256: FIXED_POLICY_ENFORCEMENT_SHA256,
    sources: POLICY_SOURCE_URLS.map((url, index) => ({
      id: sourceIds[index]!,
      url,
      retrievedAt: now.toISOString(),
      contentSha256: expectedSha256
    })),
    rulesOfEngagement: ['Reviewed fixed enforcement governs operations.'],
    inScopeTargets: ['api.github.com'],
    ineligibleCategories: ['Availability testing.'],
    severityReferences: [],
    reviewedAt: now.toISOString()
  };
}

function successfulFetch(
  url: PolicySourceUrl,
  body: string
): { fetch: PolicyFetch; attempts: () => number } {
  let attempts = 0;
  return {
    fetch: async (requestedUrl, options) => {
      attempts += 1;
      expect(attempts).toBe(1);
      expect(requestedUrl).toBe(url);
      expect(options.redirect).toBe('manual');
      expect(options.credentials).toBe('omit');
      expect(options.headers).toEqual({});
      expect(options.signal).toBeInstanceOf(AbortSignal);
      return { status: 200, text: async () => body };
    },
    attempts: () => attempts
  };
}

describe('canonicalizePolicyHtml', () => {
  it('ignores page shell, attributes, and whitespace when reviewed main semantics are unchanged', () => {
    expect(canonicalizePolicyHtml(semanticHtml)).toBe('Keep requests low.\nCafé & tea.');
    expect(canonicalizePolicyHtml(semanticHtml)).toBe(canonicalizePolicyHtml(equivalentHtml));
    expect(hashCanonicalPolicyHtml(semanticHtml)).toBe(hashCanonicalPolicyHtml(equivalentHtml));
  });

  it('normalizes common entities and Unicode NFC equivalently', () => {
    expect(canonicalizePolicyHtml(entityAndNfcHtml)).toBe(
      canonicalizePolicyHtml(entityAndNfcEquivalentHtml)
    );
  });

  it('accepts case-variant main markers and removes volatile blocks inside main', () => {
    const withVolatileBlocks = `
      <MAIN data-policy="1"><p>Keep requests low.</p><script>ignore()</script><style>.x{}</style>
      <nav>ignore</nav><footer>ignore</footer><p>Caf&eacute; &amp; tea.</p></MAIN>
    `;

    expect(canonicalizePolicyHtml(withVolatileBlocks)).toBe(canonicalizePolicyHtml(semanticHtml));
  });

  it('changes the hash when a rule inside main changes', () => {
    const changedRule = semanticHtml.replace('Keep requests low.', 'Do not send requests.');

    expect(hashCanonicalPolicyHtml(semanticHtml)).not.toBe(hashCanonicalPolicyHtml(changedRule));
  });

  it.each([
    ['missing-main', '<html><body><p>Only a shell.</p></body></html>'],
    ['multiple-main', '<main>One</main><main>Two</main>'],
    ['multiple-main', '<main>Outer <main>Inner</main></main>'],
    ['missing-main', '<mainland>Not the selected element</mainland>'],
    ['malformed-main', '<main><p>Unclosed'],
    ['malformed-main', '</main><p>Unexpected close</p>'],
    ['empty-normalized-content', '<main><nav>only navigation</nav><style>.x{}</style></main>']
  ] as const)('fails closed for %s', (code, html) => {
    contentErrorCode(() => canonicalizePolicyHtml(html), code);
  });

  it('uses UTF-8 byte counts for the cap before canonicalization and permits the exact boundary', () => {
    const encoder = new TextEncoder();
    const wrapper = '<main></main>';
    const bodyBytes = MAX_POLICY_SOURCE_BODY_BYTES - encoder.encode(wrapper).byteLength;
    const exactBody = `${'é'.repeat(Math.floor((bodyBytes - 1) / 2))}x`;
    const exactBoundary = `<main>${exactBody}</main>`;
    const oversized = `${exactBoundary}x`;

    expect(encoder.encode(exactBoundary).byteLength).toBe(MAX_POLICY_SOURCE_BODY_BYTES);
    expect(encoder.encode(oversized).byteLength).toBe(MAX_POLICY_SOURCE_BODY_BYTES + 1);
    expect(hashCanonicalPolicyHtml(exactBoundary)).toMatch(/^[a-f0-9]{64}$/);
    contentErrorCode(() => canonicalizePolicyHtml(oversized), 'source-too-large');
    contentErrorCode(() => canonicalizePolicyHtml('x'.repeat(MAX_POLICY_SOURCE_BODY_BYTES + 1)), 'source-too-large');
  });
});

describe('fetchPolicySource', () => {
  it('exports exactly the five reviewed sources in order', () => {
    expect(POLICY_SOURCE_URLS).toEqual([
      'https://bounty.github.com/rules.html',
      'https://bounty.github.com/scope.html',
      'https://bounty.github.com/targets.html',
      'https://bounty.github.com/ineligible.html',
      'https://bounty.github.com/rewards.html'
    ]);
  });

  it('exports correlated fixed source IDs and URLs', () => {
    expect(POLICY_SOURCES).toEqual([
      { id: 'rules', url: POLICY_SOURCE_URLS[0] },
      { id: 'scope', url: POLICY_SOURCE_URLS[1] },
      { id: 'targets', url: POLICY_SOURCE_URLS[2] },
      { id: 'ineligible', url: POLICY_SOURCE_URLS[3] },
      { id: 'rewards', url: POLICY_SOURCE_URLS[4] }
    ]);
  });

  it.each(POLICY_SOURCE_URLS.map((url, index) => [sourceIds[index]!, url] as const))(
    'retrieves %s with one manual, credential-free request',
    async (sourceId, url) => {
      const controlled = successfulFetch(url, semanticHtml);

      await expect(
        fetchPolicySource({
          sourceId,
          url,
          expectedSha256: '0'.repeat(64),
          dependencies: dependencies(controlled.fetch)
        })
      ).resolves.toEqual({
        sourceId,
        state: 'changed',
        checkedAt: now,
        observedSha256: expectedSha256
      });
      expect(controlled.attempts()).toBe(1);
    }
  );

  it('returns match when the independent expected canonical hash equals the observed hash', async () => {
    const controlled = successfulFetch(POLICY_SOURCE_URLS[0], semanticHtml);

    await expect(
      fetchPolicySource({
        sourceId: 'rules',
        url: POLICY_SOURCE_URLS[0],
        expectedSha256,
        dependencies: dependencies(controlled.fetch)
      })
    ).resolves.toEqual({
      sourceId: 'rules',
      state: 'match',
      checkedAt: now,
      observedSha256: expectedSha256
    });
  });

  it.each([
    ['mismatched fixed pair', 'rules' as PolicySourceId, POLICY_SOURCE_URLS[1]],
    ['unknown source ID', 'unknown' as PolicySourceId, POLICY_SOURCE_URLS[0]],
    [
      'substituted source URL',
      'rules' as PolicySourceId,
      'https://bounty.github.com/substituted.html' as PolicySourceUrl
    ]
  ] as const)('rejects %s before fetching', async (_name, sourceId, url) => {
    let attempts = 0;
    const fetch: PolicyFetch = async () => {
      attempts += 1;
      return { status: 200, text: async () => semanticHtml };
    };

    await inputErrorCode(
      () =>
        fetchPolicySource({
          sourceId,
          url,
          expectedSha256,
          dependencies: dependencies(fetch)
        }),
      'invalid_policy_source_input'
    );
    expect(attempts).toBe(0);
  });

  it('clears the timeout after a successful request', async () => {
    const controlled = successfulFetch(POLICY_SOURCE_URLS[0], semanticHtml);
    let cleared = 0;
    const clientDependencies: PolicySourceClientDependencies = {
      ...dependencies(controlled.fetch),
      clearTimeout: () => {
        cleared += 1;
      }
    };

    await fetchPolicySource({
      sourceId: 'rules',
      url: POLICY_SOURCE_URLS[0],
      expectedSha256,
      dependencies: clientDependencies
    });
    expect(cleared).toBe(1);
  });

  it('turns transport failures into unavailable results without retrying', async () => {
    let attempts = 0;
    let cleared = 0;
    const fetch: PolicyFetch = async () => {
      attempts += 1;
      throw new Error('offline');
    };

    await expect(
      fetchPolicySource({
        sourceId: 'rules',
        url: POLICY_SOURCE_URLS[0],
        expectedSha256,
        dependencies: { ...dependencies(fetch), clearTimeout: () => { cleared += 1; } }
      })
    ).resolves.toEqual({ sourceId: 'rules', state: 'unavailable', checkedAt: now });
    expect(attempts).toBe(1);
    expect(cleared).toBe(1);
  });

  it('turns a timeout into an unavailable result after exactly the fixed timeout', async () => {
    let observedDelay: number | undefined;
    let cleared = 0;
    const fetch: PolicyFetch = async (_url, options) =>
      new Promise<never>((_, reject) =>
        options.signal.addEventListener('abort', () => reject(new Error('aborted')))
      );
    const clientDependencies: PolicySourceClientDependencies = {
      ...dependencies(fetch),
      setTimeout: (callback, delayMs) => {
        observedDelay = delayMs;
        queueMicrotask(callback);
        return { kind: 'timeout' };
      },
      clearTimeout: () => {
        cleared += 1;
      }
    };

    await expect(
      fetchPolicySource({
        sourceId: 'rules',
        url: POLICY_SOURCE_URLS[0],
        expectedSha256,
        dependencies: clientDependencies
      })
    ).resolves.toEqual({ sourceId: 'rules', state: 'unavailable', checkedAt: now });
    expect(observedDelay).toBe(POLICY_SOURCE_TIMEOUT_MS);
    expect(cleared).toBe(1);
  });

  it.each([
    ['missing main', 200, '<html><body>missing</body></html>', 'missing-main'],
    ['oversized body', 200, `<main>${'x'.repeat(MAX_POLICY_SOURCE_BODY_BYTES)}</main>`, 'source-too-large']
  ] as const)('returns malformed for %s instead of unavailable', async (_name, status, body, reason) => {
    let cleared = 0;
    const fetch: PolicyFetch = async () => ({ status, text: async () => body });

    await expect(
      fetchPolicySource({
        sourceId: 'rules',
        url: POLICY_SOURCE_URLS[0],
        expectedSha256,
        dependencies: {
          ...dependencies(fetch),
          clearTimeout: () => {
            cleared += 1;
          }
        }
      })
    ).resolves.toEqual({ sourceId: 'rules', state: 'malformed', checkedAt: now, reason });
    expect(cleared).toBe(1);
  });

  it.each([300, 301, 302, 303, 307, 308, 399] as const)(
    'returns redirect status %i as malformed with one request and never reads or follows it',
    async (status) => {
      let attempts = 0;
      let textCalls = 0;
      let cleared = 0;
      const fetch: PolicyFetch = async (url) => {
        attempts += 1;
        expect(url).toBe(POLICY_SOURCE_URLS[0]);
        return {
          status,
          text: async () => {
            textCalls += 1;
            return semanticHtml;
          }
        };
      };

      await expect(
        fetchPolicySource({
          sourceId: 'rules',
          url: POLICY_SOURCE_URLS[0],
          expectedSha256,
          dependencies: {
            ...dependencies(fetch),
            clearTimeout: () => {
              cleared += 1;
            }
          }
        })
      ).resolves.toEqual({
        sourceId: 'rules',
        state: 'malformed',
        checkedAt: now,
        reason: 'redirect-response'
      });
      expect(attempts).toBe(1);
      expect(textCalls).toBe(0);
      expect(cleared).toBe(1);
    }
  );

  it.each([400, 404, 500, 503] as const)(
    'returns HTTP status %i as malformed without reading the body or retrying',
    async (status) => {
      let attempts = 0;
      let textCalls = 0;
      const fetch: PolicyFetch = async () => {
        attempts += 1;
        return {
          status,
          text: async () => {
            textCalls += 1;
            return semanticHtml;
          }
        };
      };

      await expect(
        fetchPolicySource({
          sourceId: 'rules',
          url: POLICY_SOURCE_URLS[0],
          expectedSha256,
          dependencies: dependencies(fetch)
        })
      ).resolves.toEqual({
        sourceId: 'rules',
        state: 'malformed',
        checkedAt: now,
        reason: 'http-error-response'
      });
      expect(attempts).toBe(1);
      expect(textCalls).toBe(0);
    }
  );

  it('turns body-read rejection into unavailable and clears the timeout once', async () => {
    let attempts = 0;
    let cleared = 0;
    const fetch: PolicyFetch = async () => {
      attempts += 1;
      return { status: 200, text: async () => Promise.reject(new Error('body failed')) };
    };

    await expect(
      fetchPolicySource({
        sourceId: 'rules',
        url: POLICY_SOURCE_URLS[0],
        expectedSha256,
        dependencies: {
          ...dependencies(fetch),
          clearTimeout: () => {
            cleared += 1;
          }
        }
      })
    ).resolves.toEqual({ sourceId: 'rules', state: 'unavailable', checkedAt: now });
    expect(attempts).toBe(1);
    expect(cleared).toBe(1);
  });

  it('maps returned malformed content to review-required rather than fresh-unverified', async () => {
    let attempts = 0;
    const fetch: PolicyFetch = async (url) => {
      attempts += 1;
      expect(url).toBe(POLICY_SOURCE_URLS[0]);
      return { status: 302, text: async () => semanticHtml };
    };

    const malformed = await fetchPolicySource({
      sourceId: 'rules',
      url: POLICY_SOURCE_URLS[0],
      expectedSha256,
      dependencies: dependencies(fetch)
    });
    expect(attempts).toBe(1);
    const snapshot = reviewedSnapshot();
    const retrievals = snapshot.sources.map((source) =>
      source.id === malformed.sourceId
        ? malformed
        : {
            sourceId: source.id,
            state: 'match' as const,
            checkedAt: now,
            observedSha256: source.contentSha256
          }
    );

    expect(computePolicyStatus({ snapshot, retrievals, now }).state).toBe('review-required');
  });
});
