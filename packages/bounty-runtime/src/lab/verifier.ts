import { randomBytes, randomUUID } from 'node:crypto';

import {
  labManifestSchema,
  repositoryMarkerSchema,
  sha256StableJson,
  type LabManifest,
  type RepositoryMarker
} from '@aegishub/bounty-core';

import { LabStore, LabStoreError } from './store.js';

export interface ResolvedRepository {
  readonly id: number;
  readonly nodeId: string;
  readonly ownerId: number;
  readonly ownerLogin: string;
  readonly name: string;
  readonly fullName: string;
  readonly private: boolean;
  readonly ownerKind: 'user' | 'organization';
}

export type RemoteMarker = RepositoryMarker;

export interface CreateMarkerInput {
  readonly repository: ResolvedRepository;
  readonly marker: RemoteMarker;
}

export interface DeleteMarkerInput {
  readonly repository: ResolvedRepository;
  readonly marker: RemoteMarker;
}

export interface LabEnrollmentGateway {
  resolveOwnedRepository(fullName: string, ownerToken: string): Promise<ResolvedRepository>;
  readMarker(repository: ResolvedRepository, ownerToken: string): Promise<RemoteMarker | 'missing'>;
  createMarker(input: CreateMarkerInput, ownerToken: string): Promise<RemoteMarker>;
  deleteMarker(input: DeleteMarkerInput, ownerToken: string): Promise<void>;
}

export interface ConfigurationMutationEntry {
  readonly entryId: string;
  readonly kind: 'lab-marker-create';
  readonly repositoryId: number;
  readonly inverse: 'delete-marker';
}

export interface ConfigurationMutationJournal {
  prepare(entry: ConfigurationMutationEntry): Promise<void>;
  markSent(entryId: string): Promise<void>;
  markVerified(entryId: string): Promise<void>;
  markRolledBack(entryId: string): Promise<void>;
  markDirty(entryId: string, reason: string): Promise<void>;
}

export type LabVerificationResult =
  | { readonly status: 'missing' }
  | { readonly status: 'verified'; readonly repositoryId: number; readonly markerSha256: string }
  | { readonly status: 'renamed-and-reverified'; readonly repositoryId: number; readonly markerSha256: string }
  | { readonly status: 'verified-retained'; readonly repositoryId: number; readonly markerSha256: string }
  | { readonly status: 'unverified'; readonly repositoryId: number; readonly reason: LabVerificationReason }
  | { readonly status: 'blocked'; readonly repositoryId?: number; readonly reason: LabVerificationReason }
  | { readonly status: 'dirty'; readonly repositoryId: number; readonly reason: 'rollback_failed' };

export type LabVerificationReason =
  | 'repository_not_private'
  | 'organization_owner_verification_unavailable'
  | 'lab_owner_identity_mismatch'
  | 'repository_identity_mismatch'
  | 'marker_missing'
  | 'marker_mismatch'
  | 'marker_invalid'
  | 'lab_manifest_invalid';

export type LabVerifierErrorCode =
  | 'lab_confirmation_required'
  | 'marker_exists_different'
  | 'lab_initialization_failed'
  | 'lab_dirty'
  | 'lab_owner_identity_mismatch'
  | 'lab_repository_not_private'
  | 'lab_organization_owner_verification_unavailable';

export class LabVerifierError extends Error {
  constructor(readonly code: LabVerifierErrorCode) {
    super(code);
    this.name = 'LabVerifierError';
  }
}

export interface LabVerifierOptions {
  readonly store: Pick<LabStore, 'load' | 'writeNew' | 'replaceVerified'>;
  readonly gateway: LabEnrollmentGateway;
  readonly ownerToken: () => Promise<string> | string;
  readonly journal?: ConfigurationMutationJournal;
  readonly now?: () => Date;
}

export interface LabInitInput {
  readonly repositoryFullName: string;
  readonly confirmed: boolean;
  readonly manifest?: LabManifest;
}

export class LabVerifier {
  readonly #store: LabVerifierOptions['store'];
  readonly #gateway: LabEnrollmentGateway;
  readonly #ownerToken: () => Promise<string> | string;
  readonly #journal: ConfigurationMutationJournal;
  readonly #now: () => Date;

  constructor(options: LabVerifierOptions) {
    this.#store = options.store;
    this.#gateway = options.gateway;
    this.#ownerToken = options.ownerToken;
    this.#journal = options.journal ?? new NoopConfigurationMutationJournal();
    this.#now = options.now ?? (() => new Date());
  }

  async verify(): Promise<LabVerificationResult> {
    let loaded: Awaited<ReturnType<LabVerifierOptions['store']['load']>>;
    try {
      loaded = await this.#store.load();
    } catch (error) {
      if (error instanceof LabStoreError && error.code === 'lab_manifest_missing') return { status: 'missing' };
      return { status: 'blocked', reason: 'lab_manifest_invalid' };
    }
    const manifest = parseManifest(loaded.manifest);
    const repositoryEntry = manifest.repositories[0];
    if (repositoryEntry === undefined) return { status: 'blocked', reason: 'lab_manifest_invalid' };
    const token = await this.#ownerToken();
    const repository = await this.#gateway.resolveOwnedRepository(repositoryEntry.fullName, token);
    const boundary = validateRepositoryBoundary(manifest, repository, repositoryEntry);
    if (boundary !== undefined) return { status: 'blocked', repositoryId: repository.id, reason: boundary };

    const remote = await this.#gateway.readMarker(repository, token);
    if (remote === 'missing') return { status: 'missing' };
    const markerResult = validateMarker(remote, manifest, repositoryEntry, true);
    if (markerResult === undefined) return { status: 'blocked', repositoryId: repository.id, reason: 'marker_mismatch' };

    const renamed = repository.fullName !== repositoryEntry.fullName || repository.ownerLogin !== repositoryEntry.owner || repository.name !== repositoryEntry.name;
    if (renamed) {
      const nextManifest: LabManifest = {
        ...manifest,
        repositories: manifest.repositories.map((entry, index) => index === 0
          ? { ...entry, owner: repository.ownerLogin, name: repository.name, fullName: repository.fullName }
          : entry),
        verifiedAt: this.#now().toISOString()
      };
      await this.#store.replaceVerified(loaded.sha256, nextManifest);
    }
    return {
      status: renamed ? 'renamed-and-reverified' : 'verified',
      repositoryId: repository.id,
      markerSha256: markerResult
    };
  }

  async init(input: LabInitInput): Promise<LabVerificationResult> {
    if (!input.confirmed) throw new LabVerifierError('lab_confirmation_required');
    const token = await this.#ownerToken();
    const manifest = input.manifest === undefined ? await this.loadExistingManifest() : parseManifest(input.manifest);
    const repository = await this.#gateway.resolveOwnedRepository(input.repositoryFullName, token);
    const repositoryEntry = manifest.repositories[0];
    if (repositoryEntry === undefined || repository.fullName !== input.repositoryFullName) {
      throw new LabVerifierError('lab_owner_identity_mismatch');
    }
    const boundary = validateRepositoryBoundary(manifest, repository, repositoryEntry);
    if (boundary === 'repository_not_private') throw new LabVerifierError('lab_repository_not_private');
    if (boundary === 'organization_owner_verification_unavailable') {
      throw new LabVerifierError('lab_organization_owner_verification_unavailable');
    }
    if (boundary !== undefined) throw new LabVerifierError('lab_owner_identity_mismatch');

    const existing = await this.#gateway.readMarker(repository, token);
    if (existing !== 'missing') {
      if (validateMarker(existing, manifest, repositoryEntry, true) === undefined) {
        throw new LabVerifierError('marker_exists_different');
      }
      return { status: 'verified-retained', repositoryId: repository.id, markerSha256: sha256StableJson(existing) };
    }

    const generatedMarker = createMarker(manifest, repository);
    const entryId = randomUUID();
    const journalEntry: ConfigurationMutationEntry = {
      entryId,
      kind: 'lab-marker-create',
      repositoryId: repository.id,
      inverse: 'delete-marker'
    };
    await this.#journal.prepare(journalEntry);
    let created: RemoteMarker | undefined;
    try {
      created = await this.#gateway.createMarker({ repository, marker: generatedMarker }, token);
      await this.#journal.markSent(entryId);
      const readBack = await this.#gateway.readMarker(repository, token);
      if (
        readBack === 'missing' ||
        validateMarker(readBack, manifest, repositoryEntry, false) === undefined ||
        sha256StableJson(readBack) !== sha256StableJson(generatedMarker)
      ) {
        throw new LabVerifierError('lab_initialization_failed');
      }
      const markerSha256 = sha256StableJson(readBack);
      const nextManifest = updateMarkerHash(manifest, markerSha256);
      try {
        if (input.manifest === undefined) {
          await this.#store.replaceVerified((await this.#store.load()).sha256, nextManifest);
        } else {
          await this.#store.writeNew(nextManifest);
        }
      } catch {
        throw new LabVerifierError('lab_initialization_failed');
      }
      await this.#journal.markVerified(entryId);
      return { status: 'verified-retained', repositoryId: repository.id, markerSha256 };
    } catch (error) {
      try {
        await this.#gateway.deleteMarker({ repository, marker: created ?? generatedMarker }, token);
        await this.#journal.markRolledBack(entryId);
      } catch {
        await this.#journal.markDirty(entryId, 'rollback_failed');
        throw new LabVerifierError('lab_dirty');
      }
      if (error instanceof LabVerifierError) throw error;
      throw new LabVerifierError('lab_initialization_failed');
    }
  }

  private async loadExistingManifest(): Promise<LabManifest> {
    try {
      return parseManifest((await this.#store.load()).manifest);
    } catch {
      throw new LabVerifierError('lab_initialization_failed');
    }
  }
}

function parseManifest(value: LabManifest): LabManifest {
  const parsed = labManifestSchema.safeParse(value);
  if (!parsed.success) throw new LabVerifierError('lab_initialization_failed');
  return parsed.data;
}

function validateRepositoryBoundary(
  manifest: LabManifest,
  repository: ResolvedRepository,
  entry: LabManifest['repositories'][number]
): LabVerificationReason | undefined {
  if (!repository.private) return 'repository_not_private';
  if (repository.ownerKind === 'organization' && manifest.organization === undefined) {
    return 'organization_owner_verification_unavailable';
  }
  if (manifest.organization !== undefined && repository.ownerKind !== 'organization') {
    return 'lab_owner_identity_mismatch';
  }
  const expectedOwnerId = manifest.organization?.id ?? manifest.owner.id;
  if (repository.ownerId !== expectedOwnerId || repository.ownerId !== entry.ownerId) {
    return 'lab_owner_identity_mismatch';
  }
  if (repository.id !== entry.id || repository.nodeId !== entry.nodeId) return 'repository_identity_mismatch';
  return undefined;
}

function validateMarker(
  value: unknown,
  manifest: LabManifest,
  repository: LabManifest['repositories'][number],
  requireExpectedHash: boolean
): string | undefined {
  const parsed = repositoryMarkerSchema.safeParse(value);
  if (!parsed.success) return undefined;
  if (
    parsed.data.labId !== manifest.labId ||
    parsed.data.repositoryId !== repository.id ||
    parsed.data.ownerId !== repository.ownerId
  ) return undefined;
  const markerSha256 = sha256StableJson(parsed.data);
  return !requireExpectedHash || markerSha256 === repository.markerSha256 ? markerSha256 : undefined;
}

function createMarker(manifest: LabManifest, repository: ResolvedRepository): RemoteMarker {
  const parsed = repositoryMarkerSchema.parse({
    schemaVersion: 1,
    labId: manifest.labId,
    repositoryId: repository.id,
    ownerId: repository.ownerId,
    controlNonce: randomBytes(32).toString('base64url')
  });
  return parsed;
}

function updateMarkerHash(manifest: LabManifest, markerSha256: string): LabManifest {
  return {
    ...manifest,
    repositories: manifest.repositories.map((entry, index) => index === 0 ? { ...entry, markerSha256 } : entry),
    verifiedAt: new Date().toISOString()
  };
}

class NoopConfigurationMutationJournal implements ConfigurationMutationJournal {
  async prepare(): Promise<void> {}
  async markSent(): Promise<void> {}
  async markVerified(): Promise<void> {}
  async markRolledBack(): Promise<void> {}
  async markDirty(): Promise<void> {}
}
