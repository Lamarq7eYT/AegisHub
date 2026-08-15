import { describe, expect, it } from 'vitest';
import type { PlannedOperation } from '@aegishub/bounty-core';

import { RunRateLimiter } from '../src/transport/rate-limiter.js';
import {
  GuardedGitHubTransport,
  type GuardedHttpResponse,
  type LogicalHttpExecutor
} from '../src/transport/guarded-transport.js';

const token = 'ghu_fixture_owner_access_1234567890';
const plan: PlannedOperation = {
  schemaVersion: 1,
  planId: '95f38cca-42e2-4b7d-82e6-f13f4549b2f3',
  plannedAt: '2026-08-13T12:00:00.000Z',
  labId: '95f38cca-42e2-4b7d-82e6-f13f4549b2f3',
  experimentId: 'bundled-access-boundary-v1',
  experimentVersion: 1,
  step: {
    phase: 'baseline',
    id: 'read-repository',
    operationId: 'github.rest.repos.get.v1',
    actor: 'owner',
    repositoryId: 3003,
    parameters: { owner: 'owner-fixture', repo: 'lab-fixture' }
  }
};

function response(status = 200, body: unknown = { id: 3003, node_id: 'R_lab_fixture', full_name: 'owner-fixture/lab-fixture', private: true }): GuardedHttpResponse {
  return { status, headers: { 'content-type': 'application/json', etag: 'fixture-etag', 'x-github-media-type': 'fixture-media' }, body: JSON.stringify(body) };
}

function makeExecutor(responses: Array<GuardedHttpResponse | Error>): LogicalHttpExecutor & { requests: Array<{ url: globalThis.URL; headers: globalThis.Headers; method: string }> } {
  const requests: Array<{ url: globalThis.URL; headers: globalThis.Headers; method: string }> = [];
  return {
    requests,
    async execute(request) {
      requests.push({ url: request.url, headers: request.headers, method: request.method });
      const next = responses.shift();
      if (next === undefined) throw new Error('fixture_response_exhausted');
      if (next instanceof Error) throw next;
      return next;
    }
  };
}

function makeTransport(executor: LogicalHttpExecutor, overrides: Partial<ConstructorParameters<typeof GuardedGitHubTransport>[0]> = {}) {
  return new GuardedGitHubTransport({
    executor,
    tokenProvider: { async getUsableToken() { return token; } },
    rateLimiter: new RunRateLimiter({ concurrency: 1, requestsPerSecond: 1, burst: 2 }),
    budget: { maxRequests: 10, maxMutations: 1 },
    policyFingerprint: () => 'policy-fixture-fingerprint',
    expectedPolicyFingerprint: 'policy-fixture-fingerprint',
    context: {
      labId: plan.labId,
      runId: plan.planId,
      policyVersion: 'github-bbp-v1',
      catalogVersion: '1.0.0',
      repository: { id: 3003, nodeId: 'R_lab_fixture', fullName: 'owner-fixture/lab-fixture' }
    },
    ...overrides
  });
}

describe('GuardedGitHubTransport', () => {
  it('adds one late bearer token only for authenticated actors and retains fixed metadata only', async () => {
    const executor = makeExecutor([response()]);
    const transport = makeTransport(executor);
    const observation = await transport.execute(plan, new globalThis.AbortController().signal);

    expect(executor.requests[0]?.url.origin).toBe('https://api.github.com');
    expect(executor.requests[0]?.headers.get('authorization')).toBe(`Bearer ${token}`);
    expect(executor.requests[0]?.headers.get('x-github-api-version')).toBe('2022-11-28');
    expect(executor.requests[0]?.headers.get('accept')).toBe('application/vnd.github+json');
    expect(executor.requests[0]?.headers.get('user-agent')).toBe('aegishub-bounty/0.1');
    expect(observation.headers).not.toHaveProperty('authorization');
    expect(JSON.stringify(observation)).not.toContain(token);
  });

  it('omits authentication for anonymous requests and maps ordinary denial to an observation', async () => {
    const anonymousPlan = { ...plan, step: { ...plan.step, actor: 'anonymous' as const } };
    const executor = makeExecutor([response(403, { message: 'Resource not accessible by integration' })]);
    const transport = makeTransport(executor, { tokenProvider: { async getUsableToken() { throw new Error('must_not_fetch_token'); } } });
    const observation = await transport.execute(anonymousPlan, new globalThis.AbortController().signal);

    expect(executor.requests[0]?.headers.has('authorization')).toBe(false);
    expect(observation.status).toBe(403);
    expect(observation.errorClass).toBe('access_denied');
  });

  it('stops on 401 and retries safe reads at most twice for transient failures', async () => {
    const retryExecutor = makeExecutor([new Error('network'), response(500), response()]);
    const transport = makeTransport(retryExecutor);
    await expect(transport.execute(plan, new globalThis.AbortController().signal)).resolves.toMatchObject({ status: 200 });
    expect(retryExecutor.requests).toHaveLength(3);

    const unauthorized = makeTransport(makeExecutor([response(401)]));
    await expect(unauthorized.execute(plan, new globalThis.AbortController().signal)).rejects.toMatchObject({ code: 'transport_unauthorized' });
  });

  it('does not retry mutations, maps redirects and budget exhaustion to typed stop errors', async () => {
    const mutationPlan: PlannedOperation = {
      ...plan,
      step: { ...plan.step, phase: 'cleanup', actor: 'owner', operationId: 'github.rest.contents.delete-lab-marker.v1' }
    };
    const mutationExecutor = makeExecutor([new Error('network')]);
    const transport = makeTransport(mutationExecutor);
    await expect(transport.execute(mutationPlan, new globalThis.AbortController().signal)).rejects.toMatchObject({ code: 'transport_mutation_outcome_unknown' });
    expect(mutationExecutor.requests).toHaveLength(1);

    const redirect = makeTransport(makeExecutor([{ ...response(), status: 302 }]));
    await expect(redirect.execute(plan, new globalThis.AbortController().signal)).rejects.toMatchObject({ code: 'transport_redirect' });

    const exhausted = makeTransport(makeExecutor([response()]), { budget: { maxRequests: 0, maxMutations: 0 } });
    await expect(exhausted.execute(plan, new globalThis.AbortController().signal)).rejects.toMatchObject({ code: 'transport_budget_exhausted' });
  });

  it('fails closed when the reviewed policy fingerprint changes', async () => {
    const transport = makeTransport(makeExecutor([response()]), { policyFingerprint: () => 'changed' });
    await expect(transport.execute(plan, new globalThis.AbortController().signal)).rejects.toMatchObject({ code: 'transport_policy_changed' });
  });
});
