import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import {
  GitHubDeviceFlowClient,
  IdentityManager,
  KeyringCredentialVault,
  MemoryCredentialVault,
  loadReviewedPolicySnapshot
} from '@aegishub/bounty-runtime';

import { ReadlineBountyTerminal, type BountyTerminal } from './terminal.js';

export class BountyCliError extends Error {
  readonly code: string;

  constructor(code: string, message = code) {
    super(message);
    this.name = 'BountyCliError';
    this.code = code;
  }
}

export interface PolicyStatusView {
  readonly state: string;
  readonly policyVersion: string;
  readonly warnings: readonly string[];
}

export interface BountyCliServices {
  readonly policy: {
    status(): Promise<PolicyStatusView>;
  };
  readonly auth: {
    login(actor: 'owner' | 'researcher', persist: boolean, onVerification?: (verification: { verificationUri: string; userCode: string; expiresInSeconds: number }) => Promise<void>): Promise<{ actor: string; login: string; id: number; persisted: boolean }>;
    status(): Promise<{ records: readonly unknown[]; sessionActors: readonly string[] }>;
    logout(actor: 'owner' | 'researcher'): Promise<void>;
    revokeLocal(): Promise<{ revokedActors: readonly string[]; settingsUrl?: string }>;
  };
  readonly lab: {
    init(target: string): Promise<{ labId: string; repositoryId: number }>;
    verify(): Promise<{ status: string; labId?: string }>;
    status(): Promise<{ status: string; labId?: string }>;
  };
  readonly experiment: {
    list(): Promise<readonly { id: string; version: number }[]>;
    plan(id: string): Promise<{ planId: string; fingerprint: string; operations: readonly unknown[]; budgets: Record<string, unknown> }>;
    run(id: string): Promise<{ runId: string; state: string; candidate?: { evidenceIds: readonly string[] } }>;
  };
  readonly run: {
    inspect(runId: string): Promise<unknown>;
  };
  readonly evidence: {
    export(runId: string, outputDirectory: string): Promise<{ runId: string; path: string }>;
  };
  readonly stop: {
    request(): Promise<{ requested: boolean }>;
  };
  readonly terminal: BountyTerminal;
}

export interface BountyCliServiceOptions {
  readonly workspaceRoot?: string;
  readonly terminal?: BountyTerminal;
}

export function createBountyCliServices(options: BountyCliServiceOptions = {}): BountyCliServices {
  const workspaceRoot = resolve(options.workspaceRoot ?? globalThis.process.env.INIT_CWD ?? globalThis.process.cwd());
  const terminal = options.terminal ?? new ReadlineBountyTerminal();
  const clientId = globalThis.process.env.AEGISHUB_GITHUB_APP_CLIENT_ID;
  const sessionVault = new MemoryCredentialVault();
  const keyringVault = new KeyringCredentialVault();
  const sessionIdentity = clientId === undefined ? undefined : createIdentityManager(clientId, sessionVault, terminal);
  const persistedIdentity = clientId === undefined ? undefined : createIdentityManager(clientId, keyringVault, terminal);
  const runtimeRoot = resolve(workspaceRoot, 'packages', 'bounty-runtime', 'dist');

  return {
    policy: {
      status: async () => {
        try {
          const loaded = await loadReviewedPolicySnapshot({ fileSystem: { readFile: (path) => readFile(path, 'utf8') } });
          return { state: 'current', policyVersion: loaded.snapshot.policyVersion, warnings: [] };
        } catch {
          throw new BountyCliError('policy_unavailable', 'Reviewed policy snapshot is unavailable.');
        }
      }
    },
    auth: {
      login: async (actor, persist, onVerification) => {
        const manager = persist ? persistedIdentity : sessionIdentity;
        if (manager === undefined) throw new BountyCliError('missing_client_id', 'AEGISHUB_GITHUB_APP_CLIENT_ID is required.');
        try {
          const identity = await manager.login({ actor, persist, onVerification: onVerification ?? (() => undefined) });
          return { actor, login: identity.login, id: identity.id, persisted: persist };
        } catch (error) {
          if (error instanceof BountyCliError) throw error;
          throw new BountyCliError('auth_failed', 'GitHub Device Flow authentication failed.');
        }
      },
      status: async () => ({ records: [...(await persistedIdentity?.status() ?? [])], sessionActors: [...(await sessionIdentity?.status() ?? [])].filter((record) => record.configured).map((record) => record.actor) }),
      logout: async (actor) => {
        await sessionIdentity?.logout(actor);
        await persistedIdentity?.logout(actor).catch(() => undefined);
      },
      revokeLocal: async () => {
        await sessionIdentity?.revokeLocal();
        await persistedIdentity?.revokeLocal().catch(() => undefined);
        return { revokedActors: ['owner', 'researcher'], settingsUrl: 'https://github.com/settings/applications' };
      }
    },
    lab: {
      init: async () => unavailable('lab'),
      verify: async () => unavailable('lab'),
      status: async () => unavailable('lab')
    },
    experiment: {
      list: async () => {
        const loader = new (await import('@aegishub/bounty-runtime')).ExperimentLoader({ workspaceRoot, runtimeRoot });
        const loaded = await loader.loadBuiltIn('repo.private.contents-read-boundary.v1');
        return [{ id: loaded.experiment.id, version: loaded.experiment.version }];
      },
      plan: async () => { throw new BountyCliError('lab_required', 'A verified lab is required before planning.'); },
      run: async () => { throw new BountyCliError('lab_required', 'A verified lab is required before running.'); }
    },
    run: { inspect: async () => unavailable('run') },
    evidence: { export: async () => unavailable('evidence') },
    stop: { request: async () => unavailable('stop') },
    terminal
  };
}

function createIdentityManager(clientId: string, vault: MemoryCredentialVault | KeyringCredentialVault, terminal: BountyTerminal): IdentityManager {
  return new IdentityManager({
    vault,
    deviceFlow: new GitHubDeviceFlowClient({ clientId, isInteractive: () => terminal.isInteractive() }),
    userGateway: {
      getAuthenticatedUser: async (accessToken) => {
        const response = await fetch('https://api.github.com/user', { headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/vnd.github+json' } });
        if (!response.ok) throw new Error('identity_lookup_failed');
        return response.json();
      }
    }
  });
}

function unavailable(name: string): never {
  throw new BountyCliError(`${name}_not_configured`, `${name} service is not configured.`);
}
