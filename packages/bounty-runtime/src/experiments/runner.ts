import {
  consumeApprovalGrant,
  classifyRun,
  sha256StableJson,
  type ApprovalGrant,
  type Actor,
  type BoundaryExpectation,
  type Candidate,
  type Diff,
  type DifferentialObservation,
  type ExperimentPlan,
  type Observation,
  type PolicyStatus,
  type RunManifest
} from '@aegishub/bounty-core';

import { LabStore } from '../lab/store.js';
import {
  ActiveRunLease,
  DirtyStateStore,
  type ActiveRunOptions
} from './active-run.js';
import {
  WriteAheadMutationJournal,
  type JournalMutationEntry
} from './journal.js';

export interface RunnerRepository {
  readonly id: number;
  readonly nodeId: string;
  readonly fullName: string;
}

export interface ExperimentExecutor {
  execute(operation: RunnerOperation, signal: globalThis.AbortSignal): Promise<Observation>;
}

export interface RunnerOperation {
  readonly ordinal: number;
  readonly phase: 'setup' | 'baseline' | 'probe' | 'verify' | 'repeat' | 'cleanup';
  readonly stepId: string;
  readonly actor: Actor;
  readonly operationId: string;
  readonly parameters: Record<string, import('@aegishub/bounty-core').JsonValue>;
  readonly expectedEffect: string;
  readonly cleanupOperationId: string | null;
}

export interface MutationVerification {
  readonly applied: boolean;
  readonly evidenceId: string;
}

export interface RunEvidenceSink {
  accept(run: CompletedRun): Promise<void> | void;
}

export interface RunExperimentInput {
  readonly store: LabStore;
  readonly runId: string;
  readonly labId: string;
  readonly repository: RunnerRepository;
  readonly plan: ExperimentPlan & {
    readonly planFingerprint: string;
    readonly manifestSha256: string;
    readonly policyFingerprint: string;
    readonly catalogFingerprint: string;
    readonly labId?: string;
  };
  readonly policy: Pick<PolicyStatus, 'state' | 'policyVersion'>;
  readonly policyFingerprint: () => string;
  readonly expectedPolicyFingerprint: string;
  readonly catalogFingerprint: string;
  readonly interactiveTerminal: boolean;
  readonly approvalGrant?: ApprovalGrant;
  readonly expectation: BoundaryExpectation;
  readonly impact: {
    readonly kind: 'confidentiality' | 'integrity';
    readonly summary: string;
    readonly labOwned: boolean;
  };
  readonly ineligibleClasses: readonly string[];
  readonly executor: ExperimentExecutor;
  readonly verifyMutation?: (operation: RunnerOperation, signal: globalThis.AbortSignal) => Promise<MutationVerification>;
  readonly verifyCleanup?: (operation: RunnerOperation, observation: Observation, signal: globalThis.AbortSignal) => Promise<boolean>;
  readonly evidenceSink?: RunEvidenceSink;
  readonly now?: () => Date;
  readonly activeRunOptions?: Omit<ActiveRunOptions, 'now' | 'planFingerprint'>;
}

export interface CompletedRun {
  readonly manifest: RunManifest;
  readonly observations: readonly Observation[];
  readonly diff?: Diff;
  readonly candidate?: Candidate;
  readonly reason?: string;
  readonly cleanupStatus: RunManifest['cleanupStatus'];
  readonly recovery: ReturnType<ActiveRunLease['recovery']>;
}

export type RunnerErrorCode =
  | 'runner_approval_required'
  | 'runner_approval_invalid'
  | 'runner_dirty_lab'
  | 'runner_policy_blocked'
  | 'runner_invalid_plan'
  | 'runner_cleanup_missing'
  | 'runner_journal_required'
  | 'runner_filesystem_error';

export class RunnerError extends Error {
  constructor(readonly code: RunnerErrorCode) {
    super(code);
    this.name = 'RunnerError';
  }
}

interface MutationRecord {
  readonly operation: RunnerOperation;
  readonly entryId: string;
  readonly journal: WriteAheadMutationJournal;
}

export class ExperimentRunner {
  async run(input: RunExperimentInput): Promise<CompletedRun> {
    const now = input.now ?? (() => new Date());
    this.validateInput(input);
    const dirtyStore = new DirtyStateStore(input.store, now);
    if (await dirtyStore.load()) throw new RunnerError('runner_dirty_lab');

    let lease: ActiveRunLease | undefined;
    const observations: Observation[] = [];
    const mutations: MutationRecord[] = [];
    let journal: WriteAheadMutationJournal | undefined;
    let cleanupStatus: RunManifest['cleanupStatus'] = 'not-required';
    let forcedResult: RunManifest['result'] | undefined;
    let forcedReason: string | undefined;
    let approvalConsumed = false;
    const startedAt = now().toISOString();

    try {
      lease = await ActiveRunLease.acquire(input.store, input.runId, {
        ...(input.activeRunOptions ?? {}),
        now,
        planFingerprint: input.plan.planFingerprint
      });

      for (const operation of input.plan.operations) {
        await lease.pollStopRequest();
        const preflight = this.preflight(input, lease);
        if (preflight !== undefined) {
          forcedResult = preflight.result;
          forcedReason = preflight.reason;
          break;
        }

        const runnerOperation = toRunnerOperation(operation);
        if (isMutation(runnerOperation)) {
          if (runnerOperation.cleanupOperationId === null) {
            throw new RunnerError('runner_cleanup_missing');
          }
          if (journal === undefined) {
            journal = await WriteAheadMutationJournal.create({
              workspaceRoot: input.store.workspaceRoot(),
              runId: input.runId,
              planFingerprint: input.plan.planFingerprint,
              now
            });
          }
          const entry = mutationEntry(input, runnerOperation);
          await journal.prepare(entry);
          if (!approvalConsumed) {
            if (!this.consumeApproval(input, now())) {
              throw new RunnerError('runner_approval_invalid');
            }
            approvalConsumed = true;
          }
          const mutation = { operation: runnerOperation, entryId: entry.entryId, journal };
          mutations.push(mutation);
          const outcome = await this.executeMutation(input, mutation, lease.signal(), observations);
          if (outcome === 'unknown') {
            if (journal.state(entry.entryId) === 'dirty') {
              forcedResult = 'dirty';
              forcedReason = 'mutation_verification_unavailable';
              cleanupStatus = 'failed';
              await dirtyStore.markDirty({
                runId: input.runId,
                repositoryId: input.repository.id,
                unresolvedMutationOperation: runnerOperation.operationId,
                cleanupOperation: runnerOperation.cleanupOperationId ?? 'unknown',
                journalPath: journal.path(),
                reason: 'mutation_verification_unavailable'
              });
            } else {
              forcedResult = 'inconclusive';
              forcedReason = 'mutation_outcome_unknown';
              if (journal.state(entry.entryId) === 'clean') cleanupStatus = 'complete';
            }
            break;
          }
          continue;
        }

        try {
          const observation = await input.executor.execute(runnerOperation, lease.signal());
          observations.push(observation);
          if (observation.outOfLab) {
            forcedResult = 'inconclusive';
            forcedReason = 'out_of_lab_resource';
            break;
          }
          if (this.hasStrongCandidate(input, observations, cleanupStatus)) {
            forcedReason = 'candidate_stop';
            break;
          }
        } catch (error) {
          forcedResult = isPolicyError(error) ? 'policy_blocked' : 'inconclusive';
          forcedReason = errorReason(error);
          break;
        }
      }

      if (mutations.some((mutation) => mutation.journal.state(mutation.entryId) === 'verified-applied')) {
        cleanupStatus = await this.cleanup(input, lease.signal(), mutations, observations, now, dirtyStore);
        if (cleanupStatus !== 'complete') {
          forcedResult = 'dirty';
          forcedReason = 'cleanup_unverified';
        }
      } else if (mutations.some((mutation) => mutation.journal.state(mutation.entryId) === 'clean')) {
        cleanupStatus = 'complete';
      }

      if (lease.signal().aborted && forcedResult === undefined) {
        forcedResult = 'inconclusive';
        forcedReason = 'interrupted';
      }
      const completed = this.complete(input, observations, cleanupStatus, startedAt, now, forcedResult, forcedReason, lease.recovery());
      await input.evidenceSink?.accept(completed);
      return completed;
    } finally {
      await lease?.finish();
    }
  }

  private validateInput(input: RunExperimentInput): void {
    if (input.plan.labId !== undefined && input.plan.labId !== input.labId) throw new RunnerError('runner_invalid_plan');
    if (input.plan.manifestSha256.length !== 64 || input.plan.policyFingerprint !== input.expectedPolicyFingerprint || input.plan.catalogFingerprint !== input.catalogFingerprint) {
      throw new RunnerError('runner_invalid_plan');
    }
    if (input.policy.state !== 'current') throw new RunnerError('runner_policy_blocked');
    if (input.plan.operations.some((operation) => isMutation(operation) && operation.cleanupOperationId === null)) {
      throw new RunnerError('runner_cleanup_missing');
    }
    if (input.plan.operations.some((operation) => isMutation(operation)) && (!input.interactiveTerminal || input.approvalGrant === undefined)) {
      throw new RunnerError('runner_approval_required');
    }
  }

  private hasStrongCandidate(
    input: RunExperimentInput,
    observations: readonly Observation[],
    cleanupStatus: RunManifest['cleanupStatus']
  ): boolean {
    const differential = classifyRun({
      observations: observations.map(toDifferentialObservation),
      expectation: input.expectation,
      policy: { allowed: true },
      cleanupStatus,
      independentVerification: true,
      impact: input.impact,
      ineligibleClasses: input.ineligibleClasses
    });
    return differential.state === 'anomalous' && differential.candidate !== undefined;
  }

  private preflight(input: RunExperimentInput, lease: ActiveRunLease): { result: 'policy_blocked' | 'inconclusive'; reason: string } | undefined {
    if (lease.signal().aborted) return { result: 'inconclusive', reason: 'interrupted' };
    if (input.policyFingerprint() !== input.expectedPolicyFingerprint) return { result: 'policy_blocked', reason: 'policy_changed' };
    if (input.catalogFingerprint !== input.plan.catalogFingerprint) return { result: 'policy_blocked', reason: 'catalog_changed' };
    return undefined;
  }

  private consumeApproval(input: RunExperimentInput, now: Date): boolean {
    if (input.approvalGrant === undefined) return false;
    return consumeApprovalGrant(input.approvalGrant, input.plan.planFingerprint, now);
  }

  private async executeMutation(
    input: RunExperimentInput,
    mutation: MutationRecord,
    signal: globalThis.AbortSignal,
    observations: Observation[]
  ): Promise<'applied' | 'not-applied' | 'unknown'> {
    const { operation, entryId, journal } = mutation;
    await journal.markSent(entryId);
    try {
      const observation = await input.executor.execute(operation, signal);
      observations.push(observation);
      if (observation.outOfLab) throw Object.assign(new Error('out_of_lab_resource'), { code: 'out_of_lab_resource' });
      await journal.markObserved(entryId, observation.observationId);
      const verification = await (input.verifyMutation?.(operation, signal) ?? Promise.resolve({ applied: true, evidenceId: observation.observationId }));
      if (verification.applied) {
        await journal.markVerifiedApplied(entryId, verification.evidenceId);
        return 'applied';
      }
      await journal.markVerifiedNotApplied(entryId, verification.evidenceId);
      await journal.markClean(entryId, verification.evidenceId);
      return 'not-applied';
    } catch (error) {
      if (isUnknownMutation(error)) {
        await journal.markOutcomeUnknown(entryId, errorReason(error));
        const verification = await input.verifyMutation?.(operation, signal);
        if (verification?.applied === true) {
          await journal.markVerifiedApplied(entryId, verification.evidenceId);
          return 'applied';
        }
        if (verification?.applied === false) {
          await journal.markVerifiedNotApplied(entryId, verification.evidenceId);
          await journal.markClean(entryId, verification.evidenceId);
          return 'not-applied';
        }
        await journal.markVerificationFailed(entryId, 'mutation_verification_unavailable');
        await journal.markDirty(entryId, 'mutation_verification_unavailable');
        return 'unknown';
      }
      await journal.markOutcomeUnknown(entryId, errorReason(error));
      await journal.markVerificationFailed(entryId, errorReason(error));
      await journal.markDirty(entryId, errorReason(error));
      return 'unknown';
    }
  }

  private async cleanup(
    input: RunExperimentInput,
    signal: globalThis.AbortSignal,
    mutations: readonly MutationRecord[],
    observations: Observation[],
    now: () => Date,
    dirtyStore: DirtyStateStore
  ): Promise<'complete' | 'failed'> {
    for (const mutation of [...mutations].reverse()) {
      if (mutation.journal.state(mutation.entryId) !== 'verified-applied') continue;
      const cleanupId = mutation.operation.cleanupOperationId;
      if (cleanupId === null) return 'failed';
      const cleanup: RunnerOperation = {
        ordinal: mutation.operation.ordinal,
        phase: 'cleanup',
        stepId: `${mutation.operation.stepId}:cleanup`,
        actor: 'owner',
        operationId: cleanupId,
        parameters: mutation.operation.parameters,
        expectedEffect: 'cleanup inverse operation',
        cleanupOperationId: null
      };
      try {
        await mutation.journal.markCleanupSent(mutation.entryId);
        const observation = await input.executor.execute(cleanup, signal);
        observations.push(observation);
        const verified = await (input.verifyCleanup?.(cleanup, observation, signal) ?? Promise.resolve(true));
        if (!verified) throw new Error('cleanup_verification_failed');
        await mutation.journal.markClean(mutation.entryId, observation.observationId);
      } catch (error) {
        try {
          await mutation.journal.markVerificationFailed(mutation.entryId, errorReason(error));
          await mutation.journal.markDirty(mutation.entryId, errorReason(error));
        } finally {
          await dirtyStore.markDirty({
            runId: input.runId,
            repositoryId: input.repository.id,
            unresolvedMutationOperation: mutation.operation.operationId,
            cleanupOperation: cleanupId,
            journalPath: mutation.journal.path(),
            reason: errorReason(error)
          });
        }
        return 'failed';
      }
    }
    void now;
    return 'complete';
  }

  private complete(
    input: RunExperimentInput,
    observations: readonly Observation[],
    cleanupStatus: RunManifest['cleanupStatus'],
    startedAt: string,
    now: () => Date,
    forcedResult: RunManifest['result'] | undefined,
    forcedReason: string | undefined,
    recovery: ReturnType<ActiveRunLease['recovery']>
  ): CompletedRun {
    const differential = forcedResult === undefined
      ? classifyRun({
        observations: observations.map(toDifferentialObservation),
        expectation: input.expectation,
        policy: { allowed: true },
        cleanupStatus,
        independentVerification: true,
        impact: input.impact,
        ineligibleClasses: input.ineligibleClasses
      })
      : undefined;
    const result = forcedResult ?? differential?.state ?? 'inconclusive';
    const manifest: RunManifest = {
      schemaVersion: 1,
      runId: input.runId,
      labId: input.labId,
      policyVersion: input.policy.policyVersion,
      experimentId: input.plan.experimentId,
      experimentVersion: input.plan.experimentVersion,
      startedAt,
      completedAt: now().toISOString(),
      result,
      requestCount: observations.length,
      mutationCount: input.plan.operations.filter(isMutation).length,
      cleanupStatus
    };
    const reason = forcedReason ?? differential?.reason;
    return {
      manifest,
      observations: [...observations],
      ...(differential?.diff === undefined ? {} : { diff: differential.diff }),
      ...(differential?.candidate === undefined ? {} : { candidate: differential.candidate }),
      ...(reason === undefined ? {} : { reason }),
      cleanupStatus,
      recovery
    };
  }
}

function toRunnerOperation(operation: ExperimentPlan['operations'][number]): RunnerOperation {
  return {
    ordinal: operation.ordinal,
    phase: operation.phase,
    stepId: operation.stepId,
    actor: operation.actor,
    operationId: operation.operationId,
    parameters: operation.parameters,
    expectedEffect: operation.expectedEffect,
    cleanupOperationId: operation.cleanupOperationId
  };
}

function mutationEntry(input: RunExperimentInput, operation: RunnerOperation): JournalMutationEntry {
  return {
    entryId: `${input.runId}:${operation.ordinal}`,
    kind: 'experiment-mutation',
    repositoryId: input.repository.id,
    operationOrdinal: operation.ordinal,
    catalogId: operation.operationId,
    parametersSha256: sha256StableJson(operation.parameters),
    inverseOperationId: operation.cleanupOperationId ?? 'unknown'
  };
}

function isMutation(operation: Pick<RunnerOperation, 'expectedEffect' | 'cleanupOperationId'>): boolean {
  return operation.cleanupOperationId !== null || operation.expectedEffect.toLowerCase().includes('mutation');
}

function isUnknownMutation(error: unknown): boolean {
  return errorClass(error) === 'transport_mutation_outcome_unknown' || errorClass(error) === 'mutation_outcome_unknown';
}

function isPolicyError(error: unknown): boolean {
  return errorClass(error) === 'transport_policy_changed' || errorClass(error) === 'policy_changed';
}

function errorReason(error: unknown): string {
  const reason = errorClass(error);
  return reason ?? 'runner_execution_failed';
}

function errorClass(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null || !('code' in error)) return undefined;
  const code = (error as { code?: unknown }).code;
  return typeof code === 'string' ? code : undefined;
}

function toDifferentialObservation(observation: Observation): DifferentialObservation {
  if (observation.errorClass === undefined) {
    const withoutErrorClass = { ...observation };
    delete (withoutErrorClass as { errorClass?: string }).errorClass;
    return withoutErrorClass as DifferentialObservation;
  }
  return { ...observation } as DifferentialObservation;
}
