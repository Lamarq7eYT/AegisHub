import { afterEach, describe, expect, it } from 'vitest';
import type { PlannedOperation } from '@aegishub/bounty-core';

import { GuardedGitHubTransport, GuardedTransportError } from '../../src/transport/guarded-transport.js';
import { RunRateLimiter } from '../../src/transport/rate-limiter.js';
import { FakeGithubServer } from '../support/fake-github-server.js';

const labId = '95f38cca-42e2-4b7d-82e6-f13f4549b2f3';
const runId = '3e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12';
let server: FakeGithubServer | undefined;

afterEach(async () => {
  await server?.stop();
  server = undefined;
});

describe('bounty runtime fault integration', () => {
  it('models Device Flow pending, slow_down, denial, expiry and success without logging tokens', async () => {
    server = new FakeGithubServer();
    await server.start();
    const deviceResponse = await fetch(`${server.baseUrl}/login/device`, { method: 'POST', body: 'client_id=synthetic' });
    expect(deviceResponse.status).toBe(200);
    expect((await deviceResponse.json() as { verification_uri: string }).verification_uri).toBe('https://github.com/login/device');

    server.setDeviceMode('pending');
    expect((await (await fetch(`${server.baseUrl}/login/oauth/access_token`, { method: 'POST', body: 'device_code=synthetic' })).json() as { error: string }).error).toBe('authorization_pending');
    server.setDeviceMode('slow_down');
    expect((await (await fetch(`${server.baseUrl}/login/oauth/access_token`, { method: 'POST', body: 'device_code=synthetic' })).json() as { error: string }).error).toBe('slow_down');
    server.setDeviceMode('denied');
    expect((await (await fetch(`${server.baseUrl}/login/oauth/access_token`, { method: 'POST', body: 'device_code=synthetic' })).json() as { error: string }).error).toBe('access_denied');
    server.setDeviceMode('expired');
    expect((await (await fetch(`${server.baseUrl}/login/oauth/access_token`, { method: 'POST', body: 'device_code=synthetic' })).json() as { error: string }).error).toBe('expired_token');
    server.setDeviceMode('success');
    await fetch(`${server.baseUrl}/login/oauth/access_token`, { method: 'POST', body: 'device_code=synthetic' });
    const success = await fetch(`${server.baseUrl}/login/oauth/access_token`, { method: 'POST', body: 'device_code=synthetic' });
    expect((await success.json() as { access_token: string }).access_token).toBe('synthetic-device-access-token');
    expect(JSON.stringify(server.requests)).not.toContain('synthetic-device-access-token');
  });

  it('models stable rename and changed-ID name reuse', async () => {
    server = new FakeGithubServer();
    await server.start();
    const headers = { authorization: 'Bearer owner-token' };
    const first = await (await fetch(`${server.baseUrl}/repos/owner-fixture/lab-fixture`, { headers })).json() as { id: number; node_id: string };
    server.renameRepository('renamed-lab');
    const renamed = await (await fetch(`${server.baseUrl}/repos/owner-fixture/renamed-lab`, { headers })).json() as { id: number; node_id: string };
    expect(renamed).toMatchObject({ id: first.id, node_id: first.node_id });
    server.reuseRepository('renamed-lab');
    const reused = await (await fetch(`${server.baseUrl}/repos/owner-fixture/renamed-lab`, { headers })).json() as { id: number; node_id: string };
    expect(reused.id).not.toBe(first.id);
    expect(reused.node_id).not.toBe(first.node_id);
    expect(JSON.stringify(server.requests)).not.toContain('owner-token');
  });

  it('refuses non-loopback fake server binding', () => {
    expect(() => new FakeGithubServer({ bindAddress: '0.0.0.0' })).toThrow('fake_server_loopback_only');
  });

  it.each([
    ['unauthorized', 'transport_unauthorized'],
    ['rate-limited', 'transport_rate_limited'],
    ['redirect', 'transport_redirect']
  ] as const)('stops immediately on %s without replay', async (fault, code) => {
    server = new FakeGithubServer();
    await server.start();
    server.setFault(fault);
    const transport = makeTransport(server);
    await expect(transport.execute(operation('github.rest.repos.get.v1', 'owner'), new globalThis.AbortController().signal)).rejects.toMatchObject({ code });
    expect(server.requests).toHaveLength(1);
  });

  it('blocks stale policy before sending any request', async () => {
    server = new FakeGithubServer();
    await server.start();
    const transport = makeTransport(server, 'c'.repeat(64));
    await expect(transport.execute(operation('github.rest.repos.get.v1', 'owner'), new globalThis.AbortController().signal)).rejects.toMatchObject({ code: 'transport_policy_changed' });
    expect(server.requests).toHaveLength(0);
  });

  it('rejects a repository target outside the verified lab before sending any request', async () => {
    server = new FakeGithubServer();
    await server.start();
    const transport = makeTransport(server);
    await expect(transport.execute(operation('github.rest.repos.get.v1', 'owner', 'outside-repository'), new globalThis.AbortController().signal)).rejects.toBeDefined();
    expect(server.requests).toHaveLength(0);
  });

  it('stops on a secondary rate-limit response rather than treating it as ordinary denial', async () => {
    server = new FakeGithubServer();
    await server.start();
    server.setFault('secondary-limit');
    const transport = makeTransport(server);
    await expect(transport.execute(operation('github.rest.repos.get.v1', 'owner'), new globalThis.AbortController().signal)).rejects.toMatchObject({ code: 'transport_rate_limited' });
    expect(server.requests).toHaveLength(1);
  });

  it('retries a transient safe read at most twice after the first attempt', async () => {
    server = new FakeGithubServer();
    await server.start();
    server.setFault('upstream');
    const transport = makeTransport(server);
    await expect(transport.execute(operation('github.rest.repos.get.v1', 'owner'), new globalThis.AbortController().signal)).rejects.toMatchObject({ code: 'transport_upstream_failure' });
    expect(server.requests).toHaveLength(3);
  });

  it.each(['oversized', 'secret', 'pii'] as const)('handles %s response without persisting raw body', async (fault) => {
    server = new FakeGithubServer();
    await server.start();
    server.setFault(fault);
    const transport = makeTransport(server);
    if (fault === 'oversized') {
      await expect(transport.execute(operation('github.rest.repos.get.v1', 'owner'), new globalThis.AbortController().signal)).rejects.toMatchObject({ code: 'transport_response_too_large' });
      return;
    }
    const observation = await transport.execute(operation('github.rest.repos.get.v1', 'owner'), new globalThis.AbortController().signal);
    expect(JSON.stringify(observation.normalizedBody)).not.toContain('ghp_SYNTHETIC_FAKE_TOKEN');
    expect(JSON.stringify(observation.normalizedBody)).not.toContain('synthetic@example.invalid');
  });

  it('marks an out-of-lab response and never upgrades it to a finding', async () => {
    server = new FakeGithubServer();
    await server.start();
    server.setFault('out-of-lab');
    const transport = makeTransport(server);
    const observation = await transport.execute(operation('github.rest.repos.get.v1', 'owner'), new globalThis.AbortController().signal);
    expect(observation.outOfLab).toBe(true);
  });

  it('reports lost mutation response once and never replays the mutation', async () => {
    server = new FakeGithubServer();
    await server.start();
    server.setFault('drop-after-mutation');
    const transport = makeTransport(server);
    await expect(transport.execute(operation('github.rest.contents.put-lab-marker.v1', 'owner'), new globalThis.AbortController().signal)).rejects.toMatchObject({ code: 'transport_mutation_outcome_unknown' });
    expect(server.requests).toHaveLength(1);
    expect(server.markerPresent).toBe(true);
  });

  it('does not retry cleanup mutation after cleanup failure', async () => {
    server = new FakeGithubServer();
    await server.start();
    server.setFault('cleanup-failure');
    const transport = makeTransport(server);
    await expect(transport.execute(operation('github.rest.contents.delete-lab-marker.v1', 'owner'), new globalThis.AbortController().signal)).rejects.toMatchObject({ code: 'transport_upstream_failure' });
    expect(server.requests).toHaveLength(1);
  });
});

function makeTransport(fake: FakeGithubServer, currentFingerprint = 'b'.repeat(64)): GuardedGitHubTransport {
  return new GuardedGitHubTransport({
    executor: fake.executor(),
    tokenProvider: { getUsableToken: async () => 'owner-token' },
    rateLimiter: new RunRateLimiter({ concurrency: 1, requestsPerSecond: 100, burst: 8 }),
    budget: { maxRequests: 12, maxMutations: 1 },
    policyFingerprint: () => currentFingerprint,
    expectedPolicyFingerprint: 'b'.repeat(64),
    context: {
      labId,
      runId,
      policyVersion: 'policy-v1',
      catalogVersion: '1.0.0',
      repository: { id: 3003, nodeId: 'R_lab', fullName: 'owner-fixture/lab-fixture' }
    }
  });
}

function operation(operationId: PlannedOperation['step']['operationId'], actor: 'owner' | 'researcher' | 'anonymous', repositoryName = 'lab-fixture'): PlannedOperation {
  return {
    schemaVersion: 1,
    planId: runId,
    plannedAt: '2026-08-13T12:00:00.000Z',
    labId,
    experimentId: 'repo.private.contents-read-boundary.v1',
    experimentVersion: 1,
    step: {
      id: `fault-${operationId}`,
      phase: operationId.includes('delete') ? 'cleanup' : operationId.includes('put') ? 'setup' : 'probe',
      actor,
      operationId,
      repositoryId: 3003,
      parameters: operationId.includes('put')
        ? { owner: 'owner-fixture', repo: repositoryName, message: 'aegishub: verify bounty lab', content: 'e30=' }
        : operationId.includes('delete')
          ? { owner: 'owner-fixture', repo: repositoryName, message: 'aegishub: remove bounty lab marker', sha: 'fixture-sha' }
          : { owner: 'owner-fixture', repo: repositoryName },
      repeatGroup: `fault-${operationId}`
    }
  };
}

void GuardedTransportError;
