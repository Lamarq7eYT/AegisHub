import { randomUUID } from 'node:crypto';

import { z } from 'zod';
import type { AuthenticatedActor, GithubIdentity } from '@aegishub/bounty-core';

export interface CredentialRecord {
  readonly schemaVersion: 1;
  readonly actor: AuthenticatedActor;
  readonly accessToken: string;
  readonly refreshToken?: string | undefined;
  readonly expiresAt?: string | undefined;
  readonly refreshTokenExpiresAt?: string | undefined;
  readonly identity: GithubIdentity;
  readonly createdAt: string;
}

export interface KeyringEntry {
  setPassword(value: string): void;
  getPassword(): string | null;
  deletePassword(): void;
}

export type KeyringEntryFactory = (service: string, account: string) => KeyringEntry;

export interface VaultClock {
  now(): Date;
}

export const CREDENTIAL_SERVICE = 'AegisHub Bounty Mode';
const ACCOUNT_BY_ACTOR: Readonly<Record<AuthenticatedActor, string>> = Object.freeze({
  owner: 'github-owner-v1',
  researcher: 'github-researcher-v1'
});
const credentialRecordSchema = z
  .object({
    schemaVersion: z.literal(1),
    actor: z.enum(['owner', 'researcher']),
    accessToken: z.string().min(1),
    refreshToken: z.string().min(1).optional(),
    expiresAt: z.string().datetime({ offset: true }).optional(),
    refreshTokenExpiresAt: z.string().datetime({ offset: true }).optional(),
    identity: z
      .object({
        id: z.number().int().positive().safe(),
        nodeId: z.string().min(1),
        login: z.string().min(1)
      })
      .strict(),
    createdAt: z.string().datetime({ offset: true })
  })
  .strict();

function assertActor(actor: AuthenticatedActor): asserts actor is AuthenticatedActor {
  if (actor !== 'owner' && actor !== 'researcher') {
    throw new Error('invalid_actor');
  }
}

function isExpired(record: { readonly expiresAt?: string | undefined }, now: Date): boolean {
  return record.expiresAt !== undefined && now.getTime() >= Date.parse(record.expiresAt);
}

function cloneRecord(record: CredentialRecord): CredentialRecord {
  return {
    schemaVersion: 1,
    actor: record.actor,
    accessToken: record.accessToken,
    identity: { ...record.identity },
    createdAt: record.createdAt,
    ...(record.refreshToken !== undefined ? { refreshToken: record.refreshToken } : {}),
    ...(record.expiresAt !== undefined ? { expiresAt: record.expiresAt } : {}),
    ...(record.refreshTokenExpiresAt !== undefined
      ? { refreshTokenExpiresAt: record.refreshTokenExpiresAt }
      : {})
  };
}

function clockOrDefault(clock?: VaultClock): VaultClock {
  return clock ?? { now: () => new Date() };
}

export class MemoryCredentialVault {
  readonly #records = new Map<AuthenticatedActor, CredentialRecord>();
  readonly #clock: VaultClock;

  constructor(options: { now?: () => Date } = {}) {
    this.#clock = { now: options.now ?? (() => new Date()) };
  }

  async capability(): Promise<'session'> {
    return 'session';
  }

  async get(actor: AuthenticatedActor): Promise<CredentialRecord | undefined> {
    assertActor(actor);
    const record = this.#records.get(actor);
    if (record === undefined) return undefined;
    if (isExpired(record, this.#clock.now())) {
      this.#records.delete(actor);
      return undefined;
    }
    return cloneRecord(record);
  }

  async set(actor: AuthenticatedActor, record: CredentialRecord): Promise<void> {
    assertActor(actor);
    const parsed = credentialRecordSchema.safeParse(record);
    if (!parsed.success || parsed.data.actor !== actor) {
      throw new Error('credential_record_invalid');
    }
    this.#records.set(actor, cloneRecord(parsed.data));
  }

  async delete(actor: AuthenticatedActor): Promise<void> {
    assertActor(actor);
    this.#records.delete(actor);
  }

  async clear(): Promise<void> {
    this.#records.clear();
  }
}

export interface KeyringCredentialVaultOptions {
  entryFactory?: KeyringEntryFactory;
  now?: () => Date;
}

export class KeyringCredentialVault {
  readonly #entryFactory: KeyringEntryFactory | undefined;
  readonly #clock: VaultClock;
  #nativeEntryFactory: Promise<KeyringEntryFactory> | undefined;
  #capability: 'keychain' | 'unavailable' | undefined;

  constructor(options: KeyringCredentialVaultOptions = {}) {
    this.#entryFactory = options.entryFactory;
    this.#clock = clockOrDefault(options.now === undefined ? undefined : { now: options.now });
  }

  async capability(): Promise<'keychain'> {
    if (this.#capability === 'keychain') return 'keychain';
    if (this.#capability === 'unavailable') throw new Error('keychain_unavailable');

    const account = `capability-probe-${randomUUID()}`;
    let entry: KeyringEntry | undefined;
    try {
      const entryFactory = await this.getEntryFactory();
      entry = entryFactory(CREDENTIAL_SERVICE, account);
      entry.setPassword('aegishub-capability-probe');
      if (entry.getPassword() !== 'aegishub-capability-probe') {
        throw new Error('keychain_probe_mismatch');
      }
      entry.deletePassword();
      this.#capability = 'keychain';
      return 'keychain';
    } catch {
      this.#capability = 'unavailable';
      try {
        entry?.deletePassword();
      } catch {
        // Preserve the capability failure without exposing keyring details.
      }
      throw new Error('keychain_unavailable');
    }
  }

  async get(actor: AuthenticatedActor): Promise<CredentialRecord | undefined> {
    assertActor(actor);
    await this.ensureCapability();
    const entry = (await this.getEntryFactory())(CREDENTIAL_SERVICE, ACCOUNT_BY_ACTOR[actor]);
    let serialized: string | null;
    try {
      serialized = entry.getPassword();
    } catch {
      throw new Error('keychain_unavailable');
    }
    if (serialized === null) return undefined;

    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(serialized) as unknown;
    } catch {
      await this.deleteMalformed(entry);
      throw new Error('credential_record_invalid');
    }
    const parsed = credentialRecordSchema.safeParse(parsedJson);
    if (!parsed.success || parsed.data.actor !== actor) {
      await this.deleteMalformed(entry);
      throw new Error('credential_record_invalid');
    }
    if (isExpired(parsed.data, this.#clock.now())) {
      await this.deleteMalformed(entry);
      return undefined;
    }
    return cloneRecord(parsed.data);
  }

  async set(actor: AuthenticatedActor, record: CredentialRecord): Promise<void> {
    assertActor(actor);
    const parsed = credentialRecordSchema.safeParse(record);
    if (!parsed.success || parsed.data.actor !== actor) {
      throw new Error('credential_record_invalid');
    }
    await this.ensureCapability();
    const entry = (await this.getEntryFactory())(CREDENTIAL_SERVICE, ACCOUNT_BY_ACTOR[actor]);
    try {
      entry.setPassword(JSON.stringify(parsed.data));
    } catch {
      throw new Error('keychain_unavailable');
    }
  }

  async delete(actor: AuthenticatedActor): Promise<void> {
    assertActor(actor);
    await this.ensureCapability();
    const entry = (await this.getEntryFactory())(CREDENTIAL_SERVICE, ACCOUNT_BY_ACTOR[actor]);
    try {
      entry.deletePassword();
    } catch {
      throw new Error('keychain_unavailable');
    }
  }

  async clear(): Promise<void> {
    await this.ensureCapability();
    await this.delete('owner');
    await this.delete('researcher');
  }

  private async ensureCapability(): Promise<void> {
    await this.capability();
  }

  private async getEntryFactory(): Promise<KeyringEntryFactory> {
    if (this.#entryFactory !== undefined) return this.#entryFactory;
    if (this.#nativeEntryFactory === undefined) {
      this.#nativeEntryFactory = loadNativeKeyringEntryFactory();
    }
    try {
      return await this.#nativeEntryFactory;
    } catch {
      throw new Error('keychain_unavailable');
    }
  }

  private async deleteMalformed(entry: KeyringEntry): Promise<void> {
    try {
      entry.deletePassword();
    } catch {
      // The malformed record is already rejected; do not disclose keyring details.
    }
  }
}

async function loadNativeKeyringEntryFactory(): Promise<KeyringEntryFactory> {
  try {
    const keyring = await import('@napi-rs/keyring');
    if (typeof keyring.Entry !== 'function') throw new Error('keyring_entry_unavailable');
    return (service, account) => new keyring.Entry(service, account);
  } catch {
    throw new Error('keychain_unavailable');
  }
}
