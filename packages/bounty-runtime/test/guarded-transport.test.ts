import { describe, expect, it } from 'vitest';
import { Buffer } from 'node:buffer';

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

function makeExecutor(responses: Array<GuardedHttpResponse | Error>): LogicalHttpExecutor & { requests: Array<{ url: globalThis.URL; headers: globalThis.Headers; method: string; body?: string }> } {
  const requests: Array<{ url: globalThis.URL; headers: globalThis.Headers; method: string; body?: string }> = [];
  return {
    requests,
    async execute(request) {
      requests.push({ url: request.url, headers: request.headers, method: request.method, ...(request.body === undefined ? {} : { body: request.body }) });
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

  it('stamps observations with the execution runId rather than the planId', async () => {
    const executionRunId = 'a8b7f6e5-d4c3-4b2a-9108-76543210fedc';
    const executor = makeExecutor([response()]);
    const transport = makeTransport(executor, {
      context: {
        labId: plan.labId,
        runId: executionRunId,
        policyVersion: 'github-bbp-v1',
        catalogVersion: '1.0.0',
        repository: { id: 3003, nodeId: 'R_lab_fixture', fullName: 'owner-fixture/lab-fixture' }
      }
    });

    const observation = await transport.execute(plan, new globalThis.AbortController().signal);

    expect(observation.runId).toBe(executionRunId);
    expect(observation.runId).not.toBe(plan.planId);
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

  it('sends the typed marker payload for the cataloged enrollment mutation', async () => {
    const mutationPlan: PlannedOperation = {
      ...plan,
      step: {
        ...plan.step,
        phase: 'setup',
        operationId: 'github.rest.contents.put-lab-marker.v1',
        parameters: {
          owner: 'owner-fixture',
          repo: 'lab-fixture',
          message: 'aegishub: verify bounty lab',
          content: 'eyJmaXh0dXJlIjp0cnVlfQ=='
        }
      }
    };
    const executor = makeExecutor([response(201, { content: { sha: 'fixture-sha' } })]);
    const transport = makeTransport(executor);

    await expect(transport.execute(mutationPlan, new globalThis.AbortController().signal)).resolves.toMatchObject({ status: 201 });
    expect(executor.requests[0]?.method).toBe('PUT');
    expect(executor.requests[0]?.headers.get('content-type')).toBe('application/json');
    expect(JSON.parse(executor.requests[0]?.body ?? '{}')).toEqual({
      message: 'aegishub: verify bounty lab',
      content: 'eyJmaXh0dXJlIjp0cnVlfQ=='
    });
  });

  it('sends the fixed GraphQL lab-marker document without accepting query text', async () => {
    const graphqlPlan: PlannedOperation = {
      ...plan,
      step: {
        ...plan.step,
        operationId: 'github.graphql.contents.get-lab-marker.v1' as never,
        parameters: { owner: 'owner-fixture', repo: 'lab-fixture' }
      }
    };
    const executor = makeExecutor([response(200, { data: { repository: null } })]);
    const transport = makeTransport(executor);

    await expect(transport.execute(graphqlPlan, new globalThis.AbortController().signal)).resolves.toMatchObject({ method: 'POST' });
    expect(executor.requests[0]?.url.toString()).toBe('https://api.github.com/graphql');
    expect(JSON.parse(executor.requests[0]?.body ?? '{}')).toMatchObject({
      operationName: 'RepositoryLabMarkerV1',
      variables: { owner: 'owner-fixture', repo: 'lab-fixture' }
    });
    expect(JSON.parse(executor.requests[0]?.body ?? '{}').query).toContain('query RepositoryLabMarkerV1');
    expect(JSON.stringify(graphqlPlan.step.parameters)).not.toContain('query');
  });

  it('normalizes a GraphQL lab marker without retaining the control nonce', async () => {
    const marker = { schemaVersion: 1, labId: plan.labId, repositoryId: 3003, ownerId: 1001, controlNonce: 'synthetic-control-nonce-123456' };
    const graphqlPlan: PlannedOperation = {
      ...plan,
      step: {
        ...plan.step,
        operationId: 'github.graphql.contents.get-lab-marker.v1' as never,
        parameters: { owner: 'owner-fixture', repo: 'lab-fixture' }
      }
    };
    const executor = makeExecutor([response(200, {
      data: {
        repository: {
          databaseId: 3003,
          isPrivate: true,
          object: { text: JSON.stringify(marker) }
        }
      }
    })]);
    const transport = makeTransport(executor);

    const observation = await transport.execute(graphqlPlan, new globalThis.AbortController().signal);

    expect(observation.status).toBe(200);
    expect(observation.protectedData).toBe(true);
    expect(observation.normalizedBody).toMatchObject({ marker: { labId: plan.labId, repositoryId: 3003 } });
    expect(JSON.stringify(observation)).not.toContain('synthetic-control-nonce');
  });

  it('maps a GraphQL null private repository to a denied observation without protected data', async () => {
    const graphqlPlan: PlannedOperation = {
      ...plan,
      step: {
        ...plan.step,
        operationId: 'github.graphql.contents.get-lab-marker.v1' as never,
        actor: 'researcher',
        parameters: { owner: 'owner-fixture', repo: 'lab-fixture' }
      }
    };
    const executor = makeExecutor([response(200, { data: { repository: null } })]);
    const transport = makeTransport(executor);

    const observation = await transport.execute(graphqlPlan, new globalThis.AbortController().signal);

    expect(observation.status).toBe(404);
    expect(observation.errorClass).toBe('not_found');
    expect(observation.protectedData).toBe(false);
  });

  it('normalizes a real GitHub Contents base64 marker before protected-data detection', async () => {
    const marker = { schemaVersion: 1, labId: plan.labId, repositoryId: 3003, ownerId: 1001, controlNonce: 'synthetic-control-nonce-123456' };
    const encoded = Buffer.from(JSON.stringify(marker), 'utf8').toString('base64');
    const executor = makeExecutor([response(200, { content: encoded, encoding: 'base64', sha: 'fixture-sha' })]);
    const transport = makeTransport(executor);
    const markerPlan: PlannedOperation = {
      ...plan,
      step: {
        ...plan.step,
        operationId: 'github.rest.contents.get-lab-marker.v1',
        parameters: { owner: 'owner-fixture', repo: 'lab-fixture' }
      }
    };

    const observation = await transport.execute(markerPlan, new globalThis.AbortController().signal);

    expect(observation.protectedData).toBe(true);
    expect(observation.normalizedBody).toMatchObject({ marker: { labId: plan.labId, repositoryId: 3003 } });
    expect(JSON.stringify(observation)).not.toContain('synthetic-control-nonce');
  });

  it('returns the validated full marker only through the enrollment read seam', async () => {
    const marker = { schemaVersion: 1, labId: plan.labId, repositoryId: 3003, ownerId: 1001, controlNonce: 'synthetic-control-nonce-123456' };
    const encoded = Buffer.from(JSON.stringify(marker), 'utf8').toString('base64');
    const executor = makeExecutor([response(200, { content: encoded, encoding: 'base64', sha: 'fixture-sha' })]);
    const transport = makeTransport(executor);
    const markerPlan: PlannedOperation = {
      ...plan,
      step: {
        ...plan.step,
        operationId: 'github.rest.contents.get-lab-marker.v1',
        parameters: { owner: 'owner-fixture', repo: 'lab-fixture' }
      }
    };

    await expect(transport.readMarker(markerPlan, new globalThis.AbortController().signal)).resolves.toEqual(marker);
  });

  it('does not retry mutations, maps redirects and budget exhaustion to typed stop errors', async () => {
    const mutationPlan: PlannedOperation = {
      ...plan,
      step: {
        ...plan.step,
        phase: 'cleanup',
        actor: 'owner',
        operationId: 'github.rest.contents.delete-lab-marker.v1',
        parameters: { owner: 'owner-fixture', repo: 'lab-fixture', message: 'aegishub: remove bounty lab marker', sha: 'fixture-sha' }
      }
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
