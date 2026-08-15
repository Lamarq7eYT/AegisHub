import { describe, expect, it } from 'vitest';

import {
  DeviceFlowError,
  GitHubDeviceFlowClient,
  type DeviceAuthStrategyFactory,
  type DeviceFlowStrategy
} from '../src/auth/device-flow.js';

const verification = {
  verificationUri: 'https://github.com/login/device' as const,
  userCode: 'ABCD-1234',
  expiresInSeconds: 900,
  intervalSeconds: 5
};

function makeStrategyFactory(
  authentication: {
    token: string;
    refreshToken?: string;
    expiresAt?: string;
    refreshTokenExpiresAt?: string;
  },
  seen: { options?: Record<string, unknown>; callback?: (value: typeof verification) => void }
): DeviceAuthStrategyFactory {
  return (options): DeviceFlowStrategy => {
    seen.options = options as unknown as Record<string, unknown>;
    seen.callback = options.onVerification;
    return {
      authenticate: async () => {
        await options.onVerification(verification);
        return authentication;
      }
    };
  };
}

describe('GitHubDeviceFlowClient', () => {
  it('uses only the GitHub App client ID and exposes verification ephemerally', async () => {
    const seen: { options?: Record<string, unknown>; callback?: (value: typeof verification) => void } = {};
    const displayed: string[] = [];
    const client = new GitHubDeviceFlowClient({
      clientId: 'fixture-public-client-id',
      isInteractive: () => true,
      strategyFactory: makeStrategyFactory(
        {
          token: 'ghu_fixture_access_1234567890',
          refreshToken: 'r1.fixture_refresh_1234567890',
          expiresAt: '2026-08-13T13:00:00.000Z',
          refreshTokenExpiresAt: '2026-09-13T13:00:00.000Z'
        },
        seen
      )
    });

    const credential = await client.authenticate('owner', (value) => {
      displayed.push(value.verificationUri, value.userCode);
    });

    expect(seen.options).toEqual({
      clientId: 'fixture-public-client-id',
      clientType: 'github-app',
      onVerification: expect.any(Function)
    });
    expect(seen.options).not.toHaveProperty('clientSecret');
    expect(seen.options).not.toHaveProperty('scopes');
    expect(displayed).toEqual(['https://github.com/login/device', 'ABCD-1234']);
    expect(credential).toEqual({
      actor: 'owner',
      accessToken: 'ghu_fixture_access_1234567890',
      refreshToken: 'r1.fixture_refresh_1234567890',
      expiresAt: '2026-08-13T13:00:00.000Z',
      refreshTokenExpiresAt: '2026-09-13T13:00:00.000Z'
    });
  });

  it('rejects a non-interactive terminal before requesting a device code', async () => {
    let factoryCalls = 0;
    const client = new GitHubDeviceFlowClient({
      clientId: 'fixture-public-client-id',
      isInteractive: () => false,
      strategyFactory: () => {
        factoryCalls += 1;
        return { authenticate: async () => ({ token: 'fixture-token' }) };
      }
    });

    await expect(client.authenticate('researcher', () => undefined)).rejects.toMatchObject({
      code: 'device_flow_non_interactive'
    });
    expect(factoryCalls).toBe(0);
  });

  it.each([
    ['denied', 'access_denied', 'device_flow_denied'],
    ['expired', 'expired_token', 'device_flow_expired'],
    ['slow down', 'slow_down', 'device_flow_slow_down']
  ] as const)('maps %s responses to a redacted typed error', async (_name, sourceCode, expectedCode) => {
    const client = new GitHubDeviceFlowClient({
      clientId: 'fixture-public-client-id',
      isInteractive: () => true,
      strategyFactory: () => ({
        authenticate: async () => {
          throw new Error(`${sourceCode}: ghp_fixture_secret_1234567890`);
        }
      })
    });

    try {
      await client.authenticate('owner', () => undefined);
      throw new Error('expected Device Flow failure');
    } catch (error) {
      expect(error).toBeInstanceOf(DeviceFlowError);
      expect((error as DeviceFlowError).code).toBe(expectedCode);
      expect(String(error)).not.toContain('ghp_fixture_secret_1234567890');
      expect(JSON.stringify(error)).not.toContain('ghp_fixture_secret_1234567890');
    }
  });

  it('retains only the safe OAuth error category for structured failures', async () => {
    const client = new GitHubDeviceFlowClient({
      clientId: 'fixture-public-client-id',
      isInteractive: () => true,
      strategyFactory: () => ({
        authenticate: async () => {
          const error = new Error('oauth request failed with synthetic secret ghp_fixture_secret_1234567890') as Error & { response?: { data?: { error?: string } } };
          error.response = { data: { error: 'device_flow_disabled' } };
          throw error;
        }
      })
    });

    await expect(client.authenticate('owner', () => undefined)).rejects.toMatchObject({
      code: 'device_flow_failed',
      detail: 'device_flow_disabled'
    });
  });

  it('rejects anonymous as a Device Flow actor', async () => {
    const client = new GitHubDeviceFlowClient({
      clientId: 'fixture-public-client-id',
      isInteractive: () => true,
      strategyFactory: () => ({ authenticate: async () => ({ token: 'fixture-token' }) })
    });

    await expect(client.authenticate('anonymous' as never, () => undefined)).rejects.toMatchObject({
      code: 'device_flow_invalid_actor'
    });
  });
});
