import { describe, expect, it } from 'vitest';
import type { GithubIdentity } from '@aegishub/bounty-core';

import { IdentityManager, type AuthenticatedUserGateway } from '../src/auth/identity-manager.js';
import { MemoryCredentialVault } from '../src/auth/vault.js';

const ownerIdentity = { id: 1001, nodeId: 'U_owner_fixture', login: 'owner-fixture' } as const;
const renamedOwnerIdentity = { ...ownerIdentity, login: 'owner-renamed-fixture' } as const;
const researcherIdentity = { id: 2002, nodeId: 'U_researcher_fixture', login: 'researcher-fixture' } as const;

class FakeDeviceFlow {
  readonly credentials: Record<'owner' | 'researcher', { actor: 'owner' | 'researcher'; accessToken: string }>;

  constructor() {
    this.credentials = {
      owner: { actor: 'owner', accessToken: 'ghu_fixture_owner_access_1234567890' },
      researcher: { actor: 'researcher', accessToken: 'ghu_fixture_researcher_access_1234567890' }
    };
  }

  async authenticate(actor: 'owner' | 'researcher'): Promise<{ actor: 'owner' | 'researcher'; accessToken: string }> {
    return this.credentials[actor];
  }
}

function makeGateway(identities: Record<string, GithubIdentity>): AuthenticatedUserGateway {
  return {
    getAuthenticatedUser: async (token) => {
      const identity = identities[token];
      if (identity === undefined) throw new Error('identity_lookup_fixture_failure');
      return identity;
    }
  };
}

describe('IdentityManager', () => {
  it('verifies GET /user immediately and stores the session record', async () => {
    const vault = new MemoryCredentialVault();
    const manager = new IdentityManager({
      vault,
      deviceFlow: new FakeDeviceFlow(),
      userGateway: makeGateway({
        ghu_fixture_owner_access_1234567890: ownerIdentity,
        ghu_fixture_researcher_access_1234567890: researcherIdentity
      })
    });

    expect(await manager.login({ actor: 'owner', onVerification: () => undefined, persist: true })).toEqual(ownerIdentity);
    expect(await vault.get('owner')).toMatchObject({ actor: 'owner', identity: ownerIdentity });
  });

  it('keeps unpersisted login credentials in the process session only', async () => {
    const vault = new MemoryCredentialVault();
    const manager = new IdentityManager({
      vault,
      deviceFlow: new FakeDeviceFlow(),
      userGateway: makeGateway({ ghu_fixture_owner_access_1234567890: ownerIdentity })
    });

    await manager.login({ actor: 'owner', onVerification: () => undefined });

    expect(await vault.get('owner')).toBeUndefined();
    await expect(manager.getUsableToken('owner')).resolves.toBe('ghu_fixture_owner_access_1234567890');
  });

  it('accepts a login-name change when immutable ID is unchanged', async () => {
    const vault = new MemoryCredentialVault();
    const gateway = makeGateway({ ghu_fixture_owner_access_1234567890: ownerIdentity });
    const manager = new IdentityManager({ vault, deviceFlow: new FakeDeviceFlow(), userGateway: gateway });

    await manager.login({ actor: 'owner', onVerification: () => undefined, persist: true });
    gateway.getAuthenticatedUser = async () => renamedOwnerIdentity;

    expect(await manager.login({ actor: 'owner', onVerification: () => undefined, persist: true })).toEqual(renamedOwnerIdentity);
    expect((await vault.get('owner'))?.identity.login).toBe('owner-renamed-fixture');
  });

  it('rejects owner and researcher when immutable IDs are equal before persistence', async () => {
    const vault = new MemoryCredentialVault();
    const manager = new IdentityManager({
      vault,
      deviceFlow: new FakeDeviceFlow(),
      userGateway: makeGateway({
        ghu_fixture_owner_access_1234567890: ownerIdentity,
        ghu_fixture_researcher_access_1234567890: ownerIdentity
      })
    });

    await manager.login({ actor: 'owner', onVerification: () => undefined, persist: true });
    await expect(manager.login({ actor: 'researcher', onVerification: () => undefined, persist: true })).rejects.toMatchObject({
      code: 'identity_roles_must_be_distinct'
    });
    expect(await vault.get('researcher')).toBeUndefined();
  });

  it('discards an unverified credential when identity lookup fails', async () => {
    const vault = new MemoryCredentialVault();
    const manager = new IdentityManager({
      vault,
      deviceFlow: new FakeDeviceFlow(),
      userGateway: makeGateway({})
    });

    await expect(manager.login({ actor: 'owner', onVerification: () => undefined })).rejects.toMatchObject({
      code: 'identity_lookup_failed'
    });
    expect(await vault.get('owner')).toBeUndefined();
  });

  it('deletes expired records and performs on-demand Device Flow', async () => {
    const vault = new MemoryCredentialVault({ now: () => new Date('2026-08-13T13:00:00.000Z') });
    await vault.set('owner', {
      schemaVersion: 1,
      actor: 'owner',
      accessToken: 'ghu_fixture_expired_1234567890',
      expiresAt: '2026-08-13T12:59:59.000Z',
      identity: ownerIdentity,
      createdAt: '2026-08-13T12:00:00.000Z'
    });
    const manager = new IdentityManager({
      vault,
      deviceFlow: new FakeDeviceFlow(),
      userGateway: makeGateway({ ghu_fixture_owner_access_1234567890: ownerIdentity })
    });

    expect(await manager.requireIdentity('owner', { onVerification: () => undefined, persist: true })).toEqual(ownerIdentity);
    expect((await vault.get('owner'))?.accessToken).toBe('ghu_fixture_owner_access_1234567890');
  });

  it('logs out one actor and revoke-local clears both with the explicit settings URL', async () => {
    const vault = new MemoryCredentialVault();
    const manager = new IdentityManager({
      vault,
      deviceFlow: new FakeDeviceFlow(),
      userGateway: makeGateway({
        ghu_fixture_owner_access_1234567890: ownerIdentity,
        ghu_fixture_researcher_access_1234567890: researcherIdentity
      })
    });

    await manager.login({ actor: 'owner', onVerification: () => undefined, persist: true });
    await manager.login({ actor: 'researcher', onVerification: () => undefined, persist: true });
    await manager.logout('owner');
    expect(await vault.get('owner')).toBeUndefined();
    expect(await vault.get('researcher')).toBeDefined();
    await expect(manager.revokeLocal()).resolves.toEqual({
      settingsUrl: 'https://github.com/settings/applications'
    });
    expect(await vault.get('researcher')).toBeUndefined();
  });
});
