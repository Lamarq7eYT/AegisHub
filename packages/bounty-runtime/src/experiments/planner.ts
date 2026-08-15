import { randomUUID } from 'node:crypto';

import { resolveCatalogOperation } from '../transport/operation-catalog.js';

import {
  createApprovalFingerprint,
  getOperationDescriptor,
  type Experiment,
  type ExperimentPlan as CoreExperimentPlan,
  type LabManifest,
  type PolicyStatus,
  type PlannedExperimentOperation
} from '@aegishub/bounty-core';

export interface PlannerLabState {
  readonly status: 'verified' | 'renamed-and-reverified' | 'unverified' | 'dirty' | 'blocked';
  readonly manifestSha256: string;
  readonly markerSha256: string;
}

export interface PlanExperimentInput {
  readonly experiment: Experiment;
  readonly manifest: LabManifest;
  readonly policy: PolicyStatus;
  readonly lab: PlannerLabState;
  readonly policyFingerprint: string;
  readonly catalogFingerprint: string;
  readonly now?: Date;
}

export interface ExperimentPlan extends CoreExperimentPlan {
  readonly planFingerprint: string;
  readonly manifestSha256: string;
  readonly policyFingerprint: string;
  readonly catalogFingerprint: string;
}

export type PlannerErrorCode =
  | 'planner_policy_blocked'
  | 'planner_dirty_lab'
  | 'planner_lab_unverified'
  | 'planner_capability_denied'
  | 'planner_operation_family_denied'
  | 'planner_phase_order_invalid'
  | 'planner_budget_exceeded'
  | 'planner_repeat_requirement'
  | 'planner_repository_mismatch'
  | 'planner_actor_denied'
  | 'planner_cleanup_inverse_missing'
  | 'planner_invalid_input';

export class PlannerError extends Error {
  constructor(readonly code: PlannerErrorCode) {
    super(code);
    this.name = 'PlannerError';
  }
}

const phaseOrder = new Map(['setup', 'baseline', 'probe', 'verify', 'repeat', 'cleanup'].map((phase, index) => [phase, index] as const));
const allowedCapabilities = new Set(['private-repository']);
const familyByNormalization = new Map([['repository-v1', 'repository-read-boundary'], ['marker-read-v1', 'repository-read-boundary']]);

export class ExperimentPlanner {
  plan(input: PlanExperimentInput): ExperimentPlan {
    const { experiment, manifest, policy, lab } = input;
    if (policy.state !== 'current' && experiment.budgets.maxMutations > 0) {
      throw new PlannerError('planner_policy_blocked');
    }
    if (policy.state === 'stale' || policy.state === 'review-required') throw new PlannerError('planner_policy_blocked');
    if (lab.status === 'dirty') throw new PlannerError('planner_dirty_lab');
    if (lab.status !== 'verified' && lab.status !== 'renamed-and-reverified') throw new PlannerError('planner_lab_unverified');
    if (experiment.requiredLabCapabilities.some((capability) => !allowedCapabilities.has(capability))) {
      throw new PlannerError('planner_capability_denied');
    }
    const family = familyByNormalization.get(experiment.normalizationProfile);
    if (family === undefined || !manifest.approvedOperationFamilies.includes(family)) {
      throw new PlannerError('planner_operation_family_denied');
    }
    this.assertPhaseOrder(experiment);
    this.assertRepeatRequirements(experiment);

    const repository = manifest.repositories.find((candidate) => candidate.fullName === experiment.scopeTarget);
    if (repository === undefined) throw new PlannerError('planner_repository_mismatch');
    const operations: PlannedExperimentOperation[] = [];
    let mutationCount = 0;
    for (const [ordinal, step] of experiment.steps.entries()) {
      if (step.repositoryId !== repository.id) throw new PlannerError('planner_repository_mismatch');
      const descriptor = getOperationDescriptor(step.operationId as never);
      if (descriptor.classification === 'mutation') {
        mutationCount += 1;
        if (descriptor.cleanupOperationId === undefined) throw new PlannerError('planner_cleanup_inverse_missing');
      }
      const resolved = (() => {
        try {
          return resolveCatalogOperation({
            operationId: step.operationId as never,
            parameters: step.parameters,
            context: {
              purpose: 'experiment',
              actor: step.actor,
              repository: { id: repository.id, nodeId: repository.nodeId, fullName: repository.fullName }
            }
          });
        } catch (error) {
          const message = error instanceof Error ? error.message : '';
          if (message.includes('actor')) throw new PlannerError('planner_actor_denied');
          throw new PlannerError('planner_invalid_input');
        }
      })();
      operations.push({
        ordinal: ordinal + 1,
        phase: step.phase,
        stepId: step.id,
        actor: step.actor,
        operationId: descriptor.id,
        parameters: resolved.parameters,
        expectedEffect: descriptor.classification === 'mutation' ? 'declared mutation with inverse cleanup' : 'read-only observation',
        cleanupOperationId: descriptor.cleanupOperationId ?? null
      });
    }
    if (operations.length > experiment.budgets.maxRequests || mutationCount > experiment.budgets.maxMutations) {
      throw new PlannerError('planner_budget_exceeded');
    }
    const corePlan: CoreExperimentPlan = {
      schemaVersion: 1,
      planId: randomUUID(),
      experimentId: experiment.id,
      experimentVersion: experiment.version,
      budgets: experiment.budgets,
      operations
    };
    const planFingerprint = createApprovalFingerprint({
      plan: corePlan,
      ownerId: manifest.owner.id,
      researcherId: manifest.researcher.id,
      manifestSha256: lab.manifestSha256,
      policyFingerprint: input.policyFingerprint,
      catalogFingerprint: input.catalogFingerprint
    });
    return deepFreeze({
      ...corePlan,
      planFingerprint,
      manifestSha256: lab.manifestSha256,
      policyFingerprint: input.policyFingerprint,
      catalogFingerprint: input.catalogFingerprint
    });
  }

  private assertPhaseOrder(experiment: Experiment): void {
    let previous = -1;
    for (const step of experiment.steps) {
      const current = phaseOrder.get(step.phase);
      if (current === undefined || current < previous) throw new PlannerError('planner_phase_order_invalid');
      previous = current;
    }
  }

  private assertRepeatRequirements(experiment: Experiment): void {
    const untrustedProbeCount = experiment.steps.filter((step) => step.actor === 'anonymous' && (step.phase === 'probe' || step.phase === 'repeat')).length;
    if (untrustedProbeCount < experiment.expectation.minimumConsistentUntrustedAttempts) throw new PlannerError('planner_repeat_requirement');
    if (experiment.expectation.requireOwnerRepeat && !experiment.steps.some((step) => step.actor === 'owner' && step.phase === 'repeat')) {
      throw new PlannerError('planner_repeat_requirement');
    }
  }
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}
