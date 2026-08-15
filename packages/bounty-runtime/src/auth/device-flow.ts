import { createOAuthDeviceAuth } from '@octokit/auth-oauth-device';
import type { GitHubAppStrategyOptions } from '@octokit/auth-oauth-device';

import type { AuthenticatedActor } from '@aegishub/bounty-core';

export interface DeviceVerification {
  readonly verificationUri: 'https://github.com/login/device';
  readonly userCode: string;
  readonly expiresInSeconds: number;
  readonly intervalSeconds: number;
}

export interface UnverifiedCredential {
  readonly actor: AuthenticatedActor;
  readonly accessToken: string;
  readonly refreshToken?: string;
  readonly expiresAt?: string;
  readonly refreshTokenExpiresAt?: string;
}

export interface DeviceAuthStrategyOptions {
  readonly clientId: string;
  readonly clientType: 'github-app';
  readonly onVerification: (verification: DeviceVerification) => Promise<void> | void;
}

export interface DeviceAuthenticationResult {
  readonly token: string;
  readonly refreshToken?: string;
  readonly expiresAt?: string;
  readonly refreshTokenExpiresAt?: string;
}

export interface DeviceFlowStrategy {
  authenticate(): Promise<DeviceAuthenticationResult>;
}

export type DeviceAuthStrategyFactory = (
  options: DeviceAuthStrategyOptions
) => DeviceFlowStrategy;

export interface DeviceFlowClient {
  authenticate(
    actor: AuthenticatedActor,
    onVerification: (verification: DeviceVerification) => Promise<void> | void
  ): Promise<UnverifiedCredential>;
}

export type DeviceFlowErrorCode =
  | 'device_flow_non_interactive'
  | 'device_flow_invalid_actor'
  | 'device_flow_invalid_verification'
  | 'device_flow_denied'
  | 'device_flow_expired'
  | 'device_flow_slow_down'
  | 'device_flow_failed';

export class DeviceFlowError extends Error {
  readonly code: DeviceFlowErrorCode;

  constructor(code: DeviceFlowErrorCode) {
    super(code);
    this.name = 'DeviceFlowError';
    this.code = code;
  }
}

export interface GitHubDeviceFlowClientOptions {
  readonly clientId: string;
  readonly isInteractive?: () => boolean;
  readonly strategyFactory?: DeviceAuthStrategyFactory;
}

export class GitHubDeviceFlowClient implements DeviceFlowClient {
  readonly #clientId: string;
  readonly #isInteractive: () => boolean;
  readonly #strategyFactory: DeviceAuthStrategyFactory;

  constructor(options: GitHubDeviceFlowClientOptions) {
    if (options.clientId.trim().length === 0) {
      throw new Error('missing_github_app_client_id');
    }
    this.#clientId = options.clientId;
    this.#isInteractive = options.isInteractive ?? (() => process.stdin.isTTY === true && process.stdout.isTTY === true);
    this.#strategyFactory = options.strategyFactory ?? createProductionStrategyFactory();
  }

  async authenticate(
    actor: AuthenticatedActor,
    onVerification: (verification: DeviceVerification) => Promise<void> | void
  ): Promise<UnverifiedCredential> {
    if (actor !== 'owner' && actor !== 'researcher') {
      throw new DeviceFlowError('device_flow_invalid_actor');
    }
    if (!this.#isInteractive()) {
      throw new DeviceFlowError('device_flow_non_interactive');
    }

    const strategy = this.#strategyFactory({
      clientId: this.#clientId,
      clientType: 'github-app',
      onVerification
    });

    try {
      const authentication = await strategy.authenticate();
      if (authentication.token.trim().length === 0) {
        throw new DeviceFlowError('device_flow_failed');
      }
      return {
        actor,
        accessToken: authentication.token,
        ...(authentication.refreshToken !== undefined ? { refreshToken: authentication.refreshToken } : {}),
        ...(authentication.expiresAt !== undefined ? { expiresAt: authentication.expiresAt } : {}),
        ...(authentication.refreshTokenExpiresAt !== undefined
          ? { refreshTokenExpiresAt: authentication.refreshTokenExpiresAt }
          : {})
      };
    } catch (error) {
      if (error instanceof DeviceFlowError) throw error;
      throw mapDeviceFlowError(error);
    }
  }
}

function mapVerification(verification: {
  readonly verification_uri: string;
  readonly user_code: string;
  readonly expires_in: number;
  readonly interval: number;
}): DeviceVerification {
  if (
    verification.verification_uri !== 'https://github.com/login/device' ||
    verification.user_code.trim().length === 0 ||
    !Number.isSafeInteger(verification.expires_in) ||
    verification.expires_in <= 0 ||
    !Number.isSafeInteger(verification.interval) ||
    verification.interval <= 0
  ) {
    throw new DeviceFlowError('device_flow_invalid_verification');
  }

  return {
    verificationUri: 'https://github.com/login/device',
    userCode: verification.user_code,
    expiresInSeconds: verification.expires_in,
    intervalSeconds: verification.interval
  };
}

function mapDeviceFlowError(error: unknown): DeviceFlowError {
  const code = error instanceof Error ? error.message.toLowerCase() : '';
  if (code.includes('access_denied') || code.includes('denied')) {
    return new DeviceFlowError('device_flow_denied');
  }
  if (code.includes('expired')) {
    return new DeviceFlowError('device_flow_expired');
  }
  if (code.includes('slow_down') || code.includes('slow down')) {
    return new DeviceFlowError('device_flow_slow_down');
  }
  return new DeviceFlowError('device_flow_failed');
}

function createProductionStrategyFactory(): DeviceAuthStrategyFactory {
  return (options) => {
    const octokitOptions: GitHubAppStrategyOptions = {
      clientId: options.clientId,
      clientType: 'github-app',
      onVerification: async (verification) => {
        await options.onVerification(mapVerification(verification));
      }
    };
    const strategy = createOAuthDeviceAuth(octokitOptions);
    return {
      authenticate: async () => {
        const authentication = await strategy({ type: 'oauth' });
        return {
          token: authentication.token,
          ...('refreshToken' in authentication ? { refreshToken: authentication.refreshToken } : {}),
          ...('expiresAt' in authentication ? { expiresAt: authentication.expiresAt } : {}),
          ...('refreshTokenExpiresAt' in authentication
            ? { refreshTokenExpiresAt: authentication.refreshTokenExpiresAt }
            : {})
        };
      }
    };
  };
}
