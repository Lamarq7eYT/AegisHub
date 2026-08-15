import {
  authenticatedActorSchema,
  githubIdentitySchema,
  type AuthenticatedActor,
  type GithubIdentity
} from '@aegishub/bounty-core';

import type {
  DeviceFlowClient,
  DeviceVerification,
  UnverifiedCredential
} from './device-flow.js';
import type { CredentialRecord, KeyringCredentialVault, MemoryCredentialVault } from './vault.js';

export interface AuthenticatedUserGateway {
  getAuthenticatedUser(accessToken: string): Promise<unknown>;
}

export interface LoginInput {
  readonly actor: AuthenticatedActor;
  readonly onVerification: (verification: DeviceVerification) => Promise<void> | void;
}

export interface RequireIdentityInput {
  readonly onVerification: (verification: DeviceVerification) => Promise<void> | void;
}

export interface IdentityStatus {
  readonly actor: AuthenticatedActor;
  readonly configured: boolean;
  readonly identity?: GithubIdentity;
}

export type CredentialVaultLike = MemoryCredentialVault | KeyringCredentialVault;

export type IdentityManagerOptions = {
  readonly vault: CredentialVaultLike;
  readonly deviceFlow: Pick<DeviceFlowClient, 'authenticate'>;
  readonly userGateway: AuthenticatedUserGateway;
  readonly now?: () => Date;
};

export type IdentityManagerErrorCode =
  | 'identity_invalid_actor'
  | 'identity_lookup_failed'
  | 'identity_roles_must_be_distinct'
  | 'identity_missing';

export class IdentityManagerError extends Error {
  readonly code: IdentityManagerErrorCode;

  constructor(code: IdentityManagerErrorCode) {
    super(code);
    this.name = 'IdentityManagerError';
    this.code = code;
  }
}

export class IdentityManager {
  readonly #vault: CredentialVaultLike;
  readonly #deviceFlow: Pick<DeviceFlowClient, 'authenticate'>;
  readonly #userGateway: AuthenticatedUserGateway;
  readonly #now: () => Date;

  constructor(options: IdentityManagerOptions) {
    this.#vault = options.vault;
    this.#deviceFlow = options.deviceFlow;
    this.#userGateway = options.userGateway;
    this.#now = options.now ?? (() => new Date());
  }

  async login(input: LoginInput): Promise<GithubIdentity> {
    if (!authenticatedActorSchema.safeParse(input.actor).success) {
      throw new IdentityManagerError('identity_invalid_actor');
    }

    let credential: UnverifiedCredential;
    try {
      credential = await this.#deviceFlow.authenticate(input.actor, input.onVerification);
    } catch (error) {
      if (error instanceof IdentityManagerError) throw error;
      throw error;
    }

    let identity: GithubIdentity;
    try {
      identity = githubIdentitySchema.parse(
        await this.#userGateway.getAuthenticatedUser(credential.accessToken)
      );
    } catch {
      throw new IdentityManagerError('identity_lookup_failed');
    }

    const otherActor: AuthenticatedActor = input.actor === 'owner' ? 'researcher' : 'owner';
    const otherRecord = await this.#vault.get(otherActor);
    if (otherRecord?.identity.id === identity.id) {
      throw new IdentityManagerError('identity_roles_must_be_distinct');
    }

    const record: CredentialRecord = {
      schemaVersion: 1,
      actor: input.actor,
      accessToken: credential.accessToken,
      identity,
      createdAt: this.#now().toISOString(),
      ...(credential.refreshToken !== undefined ? { refreshToken: credential.refreshToken } : {}),
      ...(credential.expiresAt !== undefined ? { expiresAt: credential.expiresAt } : {}),
      ...(credential.refreshTokenExpiresAt !== undefined
        ? { refreshTokenExpiresAt: credential.refreshTokenExpiresAt }
        : {})
    };
    await this.#vault.set(input.actor, record);
    return identity;
  }

  async requireIdentity(
    actor: AuthenticatedActor,
    input: RequireIdentityInput
  ): Promise<GithubIdentity> {
    if (!authenticatedActorSchema.safeParse(actor).success) {
      throw new IdentityManagerError('identity_invalid_actor');
    }

    const existing = await this.#vault.get(actor);
    if (existing !== undefined) return existing.identity;
    return this.login({ actor, onVerification: input.onVerification });
  }

  async getUsableToken(actor: AuthenticatedActor): Promise<string> {
    if (!authenticatedActorSchema.safeParse(actor).success) {
      throw new IdentityManagerError('identity_invalid_actor');
    }

    const record = await this.#vault.get(actor);
    if (record === undefined) throw new IdentityManagerError('identity_missing');
    return record.accessToken;
  }

  async status(): Promise<IdentityStatus[]> {
    const statuses: IdentityStatus[] = [];
    for (const actor of ['owner', 'researcher'] as const) {
      const record = await this.#vault.get(actor);
      if (record === undefined) {
        statuses.push({ actor, configured: false });
      } else {
        statuses.push({ actor, configured: true, identity: record.identity });
      }
    }
    return statuses;
  }

  async logout(actor: AuthenticatedActor): Promise<void> {
    if (!authenticatedActorSchema.safeParse(actor).success) {
      throw new IdentityManagerError('identity_invalid_actor');
    }
    await this.#vault.delete(actor);
  }

  async revokeLocal(): Promise<{ settingsUrl: 'https://github.com/settings/applications' }> {
    await this.#vault.clear();
    return { settingsUrl: 'https://github.com/settings/applications' };
  }
}
