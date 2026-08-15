import { describe, expect, it } from 'vitest';

import {
  KeyringCredentialVault,
  MemoryCredentialVault,
  type CredentialRecord,
  type KeyringEntry,
  type KeyringEntryFactory
} from '../src/auth/vault.js';

const ownerRecord: CredentialRecord = {
  schemaVersion: 1,
  actor: 'owner',
  accessToken: 'ghu_fixture_owner_access_1234567890',
  refreshToken: 'r1.fixture_owner_refresh_1234567890',
  expiresAt: '2026-08-13T13:00:00.000Z',
  identity: { id: 1001, nodeId: 'U_owner_fixture', login: 'owner-fixture' },
  createdAt: '2026-08-13T12:00:00.000Z'
};

const researcherRecord: CredentialRecord = {
  schemaVersion: 1,
  actor: 'researcher',
  accessToken: 'ghu_fixture_researcher_access_1234567890',
  refreshToken: 'r1.fixture_researcher_refresh_1234567890',
  expiresAt: '2026-08-13T13:00:00.000Z',
  identity: { id: 2002, nodeId: 'U_researcher_fixture', login: 'researcher-fixture' },
  createdAt: '2026-08-13T12:00:00.000Z'
};

class FakeEntry implements KeyringEntry {
  value: string | null = null;
  failOn: 'get' | 'set' | 'delete' | null = null;

  setPassword(value: string): void {
    if (this.failOn === 'set') throw new Error('keyring_set_fixture_failure');
    this.value = value;
  }

  getPassword(): string | null {
    if (this.failOn === 'get') throw new Error('keyring_get_fixture_failure');
    return this.value;
  }

  deletePassword(): void {
    if (this.failOn === 'delete') throw new Error('keyring_delete_fixture_failure');
    this.value = null;
  }
}

function makeFakeKeyring(): {
  entries: Map<string, FakeEntry>;
  factory: KeyringEntryFactory;
} {
  const entries = new Map<string, FakeEntry>();
  const factory: KeyringEntryFactory = (_service, account) => {
    const existing = entries.get(account);
    if (existing !== undefined) return existing;
    const entry = new FakeEntry();
    entries.set(account, entry);
    return entry;
  };
  return { entries, factory };
}

describe('MemoryCredentialVault', () => {
  it('isolates owner and researcher records and clears both', async () => {
    const vault = new MemoryCredentialVault({ now: () => new Date('2026-08-13T12:30:00.000Z') });

    await vault.set('owner', ownerRecord);
    await vault.set('researcher', researcherRecord);

    expect(await vault.get('owner')).toEqual(ownerRecord);
    expect(await vault.get('researcher')).toEqual(researcherRecord);
    await vault.delete('owner');
    expect(await vault.get('owner')).toBeUndefined();
    expect(await vault.get('researcher')).toEqual(researcherRecord);
    await vault.clear();
    expect(await vault.get('researcher')).toBeUndefined();
    expect(await vault.capability()).toBe('session');
  });

  it('deletes an expired access-token record instead of returning it', async () => {
    const vault = new MemoryCredentialVault({ now: () => new Date('2026-08-13T13:00:00.000Z') });
    await vault.set('owner', ownerRecord);

    expect(await vault.get('owner')).toBeUndefined();
    expect(await vault.get('owner')).toBeUndefined();
  });

  it('rejects anonymous without accepting it as an authenticated actor', async () => {
    const vault = new MemoryCredentialVault();

    await expect(vault.get('anonymous' as never)).rejects.toThrow('invalid_actor');
    await expect(vault.delete('anonymous' as never)).rejects.toThrow('invalid_actor');
  });
});

describe('KeyringCredentialVault', () => {
  it('stores records in separate fixed service accounts and round-trips them', async () => {
    const { entries, factory } = makeFakeKeyring();
    const vault = new KeyringCredentialVault({
      entryFactory: factory,
      now: () => new Date('2026-08-13T12:30:00.000Z')
    });

    expect(await vault.capability()).toBe('keychain');
    await vault.set('owner', ownerRecord);
    await vault.set('researcher', researcherRecord);

    expect(await vault.get('owner')).toEqual(ownerRecord);
    expect(await vault.get('researcher')).toEqual(researcherRecord);
    expect(entries.has('github-owner-v1')).toBe(true);
    expect(entries.has('github-researcher-v1')).toBe(true);
    expect(entries.get('github-owner-v1')?.value).not.toContain('Authorization');
  });

  it('deletes malformed keyring JSON and fails closed', async () => {
    const { entries, factory } = makeFakeKeyring();
    entries.set('github-owner-v1', new FakeEntry());
    entries.get('github-owner-v1')!.value = '{"actor":"owner","accessToken":';
    const vault = new KeyringCredentialVault({ entryFactory: factory });

    await expect(vault.get('owner')).rejects.toThrow('credential_record_invalid');
    expect(entries.get('github-owner-v1')?.value).toBeNull();
  });

  it('reports keychain capability failure without falling back to plaintext', async () => {
    const { factory } = makeFakeKeyring();
    const failingFactory: KeyringEntryFactory = (service, account) => {
      const entry = factory(service, account) as FakeEntry;
      entry.failOn = 'set';
      return entry;
    };
    const vault = new KeyringCredentialVault({ entryFactory: failingFactory });

    await expect(vault.capability()).rejects.toThrow('keychain_unavailable');
    await expect(vault.set('owner', ownerRecord)).rejects.toThrow('keychain_unavailable');
    await expect(vault.get('owner')).rejects.toThrow('keychain_unavailable');
  });

  it('does not include token fixtures in serialized errors', async () => {
    const { factory } = makeFakeKeyring();
    const entryFactory: KeyringEntryFactory = (service, account) => {
      const entry = factory(service, account) as FakeEntry;
      entry.failOn = 'get';
      return entry;
    };
    const vault = new KeyringCredentialVault({ entryFactory });

    try {
      await vault.get('owner');
    } catch (error) {
      expect(JSON.stringify(error)).not.toContain(ownerRecord.accessToken);
      expect(String(error)).not.toContain(ownerRecord.refreshToken);
    }
  });
});
