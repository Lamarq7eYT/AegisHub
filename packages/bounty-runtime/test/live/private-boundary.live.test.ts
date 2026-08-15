import { Buffer } from 'node:buffer';
import { createInterface } from 'node:readline/promises';
import { createReadStream, createWriteStream } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';
import {
  catalogFingerprint,
  computePolicyStatus,
  OPERATION_CATALOG,
  sha256StableJson,
  type JsonValue,
  type LabManifest,
  type PolicySourceResult,
  type PlannedOperation
} from '@aegishub/bounty-core';

import { DeviceFlowError } from '../../src/auth/device-flow.js';
import { normalizeAuthenticatedUser } from '../../src/auth/identity-manager.js';

import {
  AtomicEvidenceWriter,
  ExperimentLoader,
  ExperimentPlanner,
  ExperimentRunner,
  fetchPolicySource,
  GitHubDeviceFlowClient,
  GuardedGitHubTransport,
  IdentityManager,
  LabStore,
  LabVerifier,
  MemoryCredentialVault,
  PolicyMonitor,
  RunRateLimiter,
  WriteAheadMutationJournal,
  POLICY_SOURCES,
  type DeviceVerification,
  type PolicySourceClientDependencies,
  type GuardedHttpResponse,
  type LabEnrollmentGateway,
  type ResolvedRepository
} from '../../src/index.js';

const live = describe.skipIf(globalThis.process.env.AEGISHUB_BOUNTY_LIVE !== '1');
const experimentId = 'repo.private.contents-read-boundary.v1';

live('private contents boundary live validation', () => {
  it('runs the two-account owned-lab boundary and writes sanitized expected evidence', async () => {
    requireInteractiveTerminal();
    const clientId = globalThis.process.env.AEGISHUB_GITHUB_APP_CLIENT_ID?.trim();
    if (clientId === undefined || clientId.length === 0) throw new Error('live_gate_missing_public_client_id');

    const repositoryFullName = globalThis.process.env.AEGISHUB_BOUNTY_LAB_REPOSITORY?.trim() || 'LlewxamDev/aegishub-bounty-lab-2026';
    const workspaceRoot = resolve(globalThis.process.env.INIT_CWD ?? globalThis.process.cwd());
    const runtimeRoot = resolve(import.meta.dirname, '../..');
    const policyMonitor = createPolicyMonitor();
    const policyFingerprint = await policyMonitor.plan();
    const policy = await policyMonitor.checkFreshnessBeforeExecution();
    if (policy.state !== 'current') throw new Error(`live_gate_policy_${policy.state}`);

    const identity = createIdentityManager(clientId);
    await login(identity, 'owner');
    globalThis.process.stdout.write('owner device flow completed; resolving identity\n');
    await login(identity, 'researcher');
    globalThis.process.stdout.write('researcher device flow completed; resolving identity\n');
    const statuses = await identity.status();
    const ownerStatus = statuses.find((status) => status.actor === 'owner');
    const researcherStatus = statuses.find((status) => status.actor === 'researcher');
    if (ownerStatus?.identity === undefined || researcherStatus?.identity === undefined) throw new Error('live_gate_identity_missing');
    if (ownerStatus.identity.id === researcherStatus.identity.id) throw new Error('live_gate_identity_not_distinct');

    const store = new LabStore(workspaceRoot);
    const gateway = createLabGateway(identity, policyFingerprint, policy.policyVersion, policyMonitor);
    const verifier = new LabVerifier({
      store,
      gateway,
      ownerToken: () => identity.getUsableToken('owner'),
      journal: await createLabJournal(workspaceRoot, repositoryFullName),
      now: () => new Date()
    });

    let verification = await verifier.verify();
    if (verification.status !== 'verified' && verification.status !== 'renamed-and-reverified') {
      const repository = await gateway.resolveOwnedRepository(repositoryFullName, await identity.getUsableToken('owner'));
      await requireTypedConfirmation(`INIT ${repository.id}`, 'matrícula do laboratório');
      const existing = await safeLoad(store);
      const manifest = existing?.manifest ?? freshManifest(repository, ownerStatus.identity, researcherStatus.identity);
      verification = await verifier.init({ repositoryFullName, confirmed: true, ...(existing === undefined ? { manifest } : {}) });
    }
    if (verification.status !== 'verified' && verification.status !== 'renamed-and-reverified' && verification.status !== 'verified-retained') {
      throw new Error(`live_gate_lab_${verification.status}`);
    }
    await policyMonitor.beforeOperation();
    const labState = await verifier.verify();
    if (labState.status !== 'verified' && labState.status !== 'renamed-and-reverified') throw new Error(`live_gate_lab_reverification_${labState.status}`);

    const loadedLab = await store.load();
    const manifest = loadedLab.manifest;
    const repositoryEntry = manifest.repositories[0];
    if (repositoryEntry === undefined) throw new Error('live_gate_repository_missing');
    const loadedExperiment = await new ExperimentLoader({ workspaceRoot, runtimeRoot }).loadBuiltIn(experimentId);
    const catalogHash = catalogFingerprint(OPERATION_CATALOG);
    const plan = new ExperimentPlanner().plan({
      experiment: loadedExperiment.experiment,
      manifest,
      policy,
      lab: { status: 'verified', manifestSha256: loadedLab.sha256, markerSha256: repositoryEntry.markerSha256 },
      policyFingerprint,
      catalogFingerprint: catalogHash
    });
    const runId = randomUUID();
    const runTransport = createTransport(identity, policyFingerprint, policy.policyVersion, runId, plan.budgets.maxRequests, 0, manifest.labId, { id: repositoryEntry.id, nodeId: repositoryEntry.nodeId, fullName: repositoryEntry.fullName });
    const evidence = new AtomicEvidenceWriter({
      workspaceRoot,
      lab: {
        labId: manifest.labId,
        ownerId: manifest.owner.id,
        researcherId: manifest.researcher.id,
        repository: { id: repositoryEntry.id, nodeId: repositoryEntry.nodeId, owner: repositoryEntry.owner, name: repositoryEntry.name, fullName: repositoryEntry.fullName },
        markerSha256: repositoryEntry.markerSha256
      },
      policy,
      policyExcerptIds: ['rules', 'scope', 'targets', 'ineligible', 'rewards'],
      experiment: loadedExperiment.experiment,
      plan
    });
    const runner = new ExperimentRunner();
    const completed = await runner.run({
      store,
      runId,
      labId: manifest.labId,
      repository: { id: repositoryEntry.id, nodeId: repositoryEntry.nodeId, fullName: repositoryEntry.fullName },
      plan,
      policy: { state: policy.state, policyVersion: policy.policyVersion },
      policyFingerprint: () => policyFingerprint,
      expectedPolicyFingerprint: policyFingerprint,
      catalogFingerprint: catalogHash,
      interactiveTerminal: true,
      expectation: loadedExperiment.experiment.expectation,
      impact: { kind: 'confidentiality', summary: 'Synthetic marker owned by the configured lab owner.', labOwned: true },
      ineligibleClasses: [],
      executor: {
        execute: async (operation, signal) => {
          await policyMonitor.beforeOperation();
          return runTransport.execute(toPlannedOperation(operation, plan, loadedExperiment.experiment.steps[operation.ordinal - 1]?.repeatGroup, repositoryEntry.id), signal);
        }
      },
      evidenceSink: evidence
    });

    expect(completed.manifest.result).toBe('expected');
    expect(completed.candidate).toBeUndefined();
    expect(completed.observations).toHaveLength(plan.operations.length);
    expect(completed.observations.filter((observation) => observation.actor === 'owner').every((observation) => observation.status === 200)).toBe(true);
    expect(completed.observations.filter((observation) => observation.actor === 'researcher' || observation.actor === 'anonymous').every((observation) => observation.status === 403 || observation.status === 404)).toBe(true);

    const inspected = await evidence.inspect(runId);
    expect(inspected.verified).toBe(true);
    expect(inspected.manifest.result).toBe('expected');
    expect(JSON.stringify(inspected)).not.toContain('controlNonce');
    expect(JSON.stringify(inspected)).not.toMatch(/(?:gh[pusr]_\w+|github_pat_)/u);
    globalThis.process.stdout.write(`live evidence bundle: ${inspected.path}\n`);
  }, 900_000);
});

function requireInteractiveTerminal(): void {
  if (globalThis.process.env.AEGISHUB_BOUNTY_LIVE_TTY_ASSERTED !== '1') throw new Error('live_gate_requires_interactive_tty');
}

function createIdentityManager(clientId: string): IdentityManager {
  const vault = new MemoryCredentialVault();
  return new IdentityManager({
    vault,
    deviceFlow: new GitHubDeviceFlowClient({ clientId, isInteractive: () => true }),
    userGateway: {
      getAuthenticatedUser: async (accessToken) => {
        const response = await globalThis.fetch('https://api.github.com/user', {
          method: 'GET',
          headers: { authorization: `Bearer ${accessToken}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' },
          redirect: 'manual',
          credentials: 'omit'
        });
        globalThis.process.stdout.write(`identity lookup response: ${response.status}\n`);
        if (!response.ok) throw new Error('identity_lookup_failed');
        return normalizeAuthenticatedUser(await response.json());
      }
    }
  });
}

async function login(identity: IdentityManager, actor: 'owner' | 'researcher'): Promise<void> {
  try {
    await identity.login({
      actor,
      persist: false,
      onVerification: async (verification: DeviceVerification) => {
        globalThis.process.stdout.write(`Authorize ${actor} at ${verification.verificationUri} with code ${verification.userCode} (expires in ${verification.expiresInSeconds}s).\n`);
      }
    });
  } catch (error) {
    if (error instanceof DeviceFlowError) globalThis.process.stdout.write(`device flow ${actor} failed: ${error.detail ?? 'unknown'}\n`);
    throw error;
  }
}

function createPolicyMonitor(): PolicyMonitor {
  return new PolicyMonitor({
    fileSystem: { readFile: (path) => readFile(path, 'utf8') },
    checkRemoteFreshness: async (snapshot) => {
      const retrievals: PolicySourceResult[] = [];
      for (const source of POLICY_SOURCES) {
        const reviewed = snapshot.sources.find((candidate) => candidate.id === source.id);
        if (reviewed === undefined) throw new Error('policy_source_missing');
        retrievals.push(await fetchPolicySource({ sourceId: source.id, url: source.url, expectedSha256: reviewed.contentSha256, dependencies: policyDependencies() }));
      }
      return computePolicyStatus({ snapshot, retrievals, now: new Date() });
    }
  });
}

function policyDependencies(): PolicySourceClientDependencies {
  return {
    fetch: async (url, options) => {
      const response = await globalThis.fetch(url, {
        redirect: options.redirect,
        credentials: options.credentials,
        headers: options.headers,
        signal: options.signal as globalThis.AbortSignal
      });
      return { status: response.status, text: () => response.text() };
    },
    now: () => new Date(),
    createAbortController: () => {
      const controller = new globalThis.AbortController();
      return { signal: controller.signal, abort: () => controller.abort() };
    },
    setTimeout: (callback, delayMs) => globalThis.setTimeout(callback, delayMs),
    clearTimeout: (timer) => globalThis.clearTimeout(timer as ReturnType<typeof globalThis.setTimeout>)
  };
}

function createTransport(identity: IdentityManager, policyFingerprint: string, policyVersion: string, runId: string, maxRequests: number, maxMutations: number, labId = '00000000-0000-4000-8000-000000000000', repository = { id: 1, nodeId: 'pending', fullName: 'pending/pending' }): GuardedGitHubTransport {
  const executor = {
    async execute(request: { method: string; url: globalThis.URL; headers: globalThis.Headers; redirect: 'manual'; credentials: 'omit'; signal: globalThis.AbortSignal; body?: string }): Promise<GuardedHttpResponse> {
      const timeoutController = new globalThis.AbortController();
      const timer = globalThis.setTimeout(() => timeoutController.abort(), 20_000);
      const onAbort = () => timeoutController.abort();
      request.signal.addEventListener('abort', onAbort, { once: true });
      globalThis.process.stdout.write(`github request started: ${request.method}\n`);
      try {
        const response = await globalThis.fetch(request.url, {
          method: request.method,
          headers: request.headers,
          redirect: request.redirect,
          credentials: request.credentials,
          signal: globalThis.AbortSignal.any([request.signal, timeoutController.signal]),
          ...(request.body === undefined ? {} : { body: request.body })
        });
        const headers: Record<string, string> = {};
        response.headers.forEach((value, name) => { headers[name] = value; });
        const body = await response.text();
        globalThis.process.stdout.write(`github response received: ${response.status}\n`);
        return { status: response.status, headers, body };
      } finally {
        globalThis.clearTimeout(timer);
        request.signal.removeEventListener('abort', onAbort);
      }
    }
  };
  return new GuardedGitHubTransport({
    executor,
    tokenProvider: { getUsableToken: (actor) => identity.getUsableToken(actor) },
    rateLimiter: new RunRateLimiter({ concurrency: 1, requestsPerSecond: 1, burst: 2 }),
    budget: { maxRequests, maxMutations },
    policyFingerprint: () => policyFingerprint,
    expectedPolicyFingerprint: policyFingerprint,
    context: {
      labId,
      runId,
      policyVersion,
      catalogVersion: '1.0.0',
      repository
    }
  });
}

function createLabGateway(identity: IdentityManager, policyFingerprint: string, policyVersion: string, policyMonitor: PolicyMonitor): LabEnrollmentGateway {
  const transportFor = (repository: ResolvedRepository, runId = randomUUID()) => createTransport(identity, policyFingerprint, policyVersion, runId, 20, 2, '00000000-0000-4000-8000-000000000000', { id: repository.id, nodeId: repository.nodeId, fullName: repository.fullName });
  return {
    resolveOwnedRepository: async (fullName) => {
      await policyMonitor.beforeOperation();
      const repository = splitFullName(fullName);
      const operation = enrollmentOperation('github.rest.repos.get.v1', repository, 'owner');
      const observation = await transportFor(repository).execute(operation, new globalThis.AbortController().signal);
      return parseRepository(observation.normalizedBody);
    },
    readMarker: async (repository) => {
      await policyMonitor.beforeOperation();
      return transportFor(repository).readMarker(enrollmentOperation('github.rest.contents.get-lab-marker.v1', repository, 'owner'), new globalThis.AbortController().signal);
    },
    createMarker: async ({ repository, marker }) => {
      await policyMonitor.beforeOperation();
      const operation = enrollmentOperation('github.rest.contents.put-lab-marker.v1', repository, 'owner', {
        message: 'aegishub: verify bounty lab',
        content: Buffer.from(JSON.stringify(marker), 'utf8').toString('base64')
      });
      const observation = await transportFor(repository).execute(operation, new globalThis.AbortController().signal);
      if (observation.status !== 200 && observation.status !== 201) throw new Error('lab_marker_create_failed');
      return marker;
    },
    deleteMarker: async ({ repository }) => {
      await policyMonitor.beforeOperation();
      const observation = await transportFor(repository).execute(enrollmentOperation('github.rest.contents.get-lab-marker.v1', repository, 'owner'), new globalThis.AbortController().signal);
      if (observation.status === 404) return;
      const sha = isJsonObject(observation.normalizedBody) && typeof observation.normalizedBody.sha === 'string' ? observation.normalizedBody.sha : undefined;
      if (sha === undefined) throw new Error('lab_marker_sha_missing_for_rollback');
      const operation = enrollmentOperation('github.rest.contents.delete-lab-marker.v1', repository, 'owner', { message: 'aegishub: remove bounty lab marker', sha });
      const deletion = await transportFor(repository).execute(operation, new globalThis.AbortController().signal);
      if (deletion.status !== 200 && deletion.status !== 204) throw new Error('lab_marker_delete_failed');
    }
  };
}

function enrollmentOperation(operationId: string, repository: ResolvedRepository, actor: 'owner', parameters: Record<string, JsonValue> = {}): PlannedOperation {
  return {
    schemaVersion: 1,
    planId: randomUUID(),
    plannedAt: new Date().toISOString(),
    labId: '00000000-0000-4000-8000-000000000000',
    experimentId: 'lab-enrollment',
    experimentVersion: 1,
    step: {
      phase: operationId.includes('put') ? 'setup' : operationId.includes('delete') ? 'cleanup' : 'setup',
      id: `lab-${operationId}`,
      operationId,
      actor,
      repositoryId: repository.id,
      parameters: { owner: repository.ownerLogin, repo: repository.name, ...parameters }
    }
  };
}

function toPlannedOperation(operation: { ordinal: number; phase: PlannedOperation['step']['phase']; stepId: string; actor: PlannedOperation['step']['actor']; operationId: string; parameters: Record<string, JsonValue> }, plan: { planId: string; experimentId: string; experimentVersion: number; labId?: string }, repeatGroup: string | undefined, repositoryId: number): PlannedOperation {
  return {
    schemaVersion: 1,
    planId: plan.planId,
    plannedAt: new Date().toISOString(),
    labId: plan.labId ?? '00000000-0000-4000-8000-000000000000',
    experimentId: plan.experimentId,
    experimentVersion: plan.experimentVersion,
    step: {
      phase: operation.phase,
      id: operation.stepId,
      operationId: operation.operationId,
      actor: operation.actor,
      repositoryId,
      parameters: operation.parameters,
      ...(repeatGroup === undefined ? {} : { repeatGroup })
    }
  };
}

function parseRepository(value: JsonValue): ResolvedRepository {
  if (!isJsonObject(value) || typeof value.id !== 'number' || typeof value.node_id !== 'string' || typeof value.full_name !== 'string' || typeof value.private !== 'boolean' || !isJsonObject(value.owner) || typeof value.owner.id !== 'number' || typeof value.owner.login !== 'string') {
    throw new Error('lab_repository_response_invalid');
  }
  return {
    id: value.id,
    nodeId: value.node_id,
    ownerId: value.owner.id,
    ownerLogin: value.owner.login,
    name: value.full_name.slice(value.full_name.indexOf('/') + 1),
    fullName: value.full_name,
    private: value.private,
    ownerKind: value.owner.type === 'Organization' ? 'organization' : 'user'
  };
}

function splitFullName(fullName: string): ResolvedRepository {
  const slash = fullName.indexOf('/');
  if (slash <= 0 || slash === fullName.length - 1) throw new Error('live_gate_repository_name_invalid');
  return { id: 1, nodeId: 'pending', ownerId: 1, ownerLogin: fullName.slice(0, slash), name: fullName.slice(slash + 1), fullName, private: true, ownerKind: 'user' };
}

function freshManifest(repository: ResolvedRepository, owner: { id: number; nodeId: string; login: string }, researcher: { id: number; nodeId: string; login: string }): LabManifest {
  const timestamp = new Date().toISOString();
  return {
    schemaVersion: 1,
    labId: randomUUID(),
    githubHost: 'github.com',
    owner,
    researcher,
    repositories: [{ id: repository.id, nodeId: repository.nodeId, ownerId: repository.ownerId, owner: repository.ownerLogin, name: repository.name, fullName: repository.fullName, markerSha256: '0'.repeat(64) }],
    approvedOperationFamilies: ['repository-read-boundary'],
    budgets: { concurrency: 1, requestsPerSecond: 1, burst: 2, maxRequests: 12, maxMutations: 10, timeoutMs: 20_000, maxReadRetries: 2, maxMutationRetries: 0 },
    retention: { maxResponseBytes: 262_144, keepRuns: 20 },
    createdAt: timestamp,
    verifiedAt: timestamp
  };
}

async function safeLoad(store: LabStore): Promise<Awaited<ReturnType<LabStore['load']>> | undefined> {
  try { return await store.load(); } catch { return undefined; }
}

async function createLabJournal(workspaceRoot: string, repositoryFullName: string): Promise<WriteAheadMutationJournal> {
  const journalId = randomUUID();
  try {
    return await WriteAheadMutationJournal.create({ workspaceRoot, runId: journalId, planFingerprint: sha256StableJson({ repositoryFullName, purpose: 'lab-init' }) });
  } catch (error) {
    if (error instanceof Error && error.message === 'journal_exists') return WriteAheadMutationJournal.open({ workspaceRoot, runId: journalId, planFingerprint: sha256StableJson({ repositoryFullName, purpose: 'lab-init' }) });
    throw error;
  }
}

async function requireTypedConfirmation(expected: string, purpose: string): Promise<void> {
  const terminalInput = createReadStream('/dev/tty');
  const terminalOutput = createWriteStream('/dev/tty');
  const readline = createInterface({ input: terminalInput, output: terminalOutput });
  try {
    const answer = await readline.question(`Type ${expected} to approve ${purpose}: `);
    if (answer.trim() !== expected) throw new Error('live_gate_confirmation_invalid');
  } finally {
    readline.close();
    terminalInput.destroy();
    terminalOutput.end();
  }
}

function isJsonObject(value: JsonValue | undefined): value is { readonly [key: string]: JsonValue } {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
