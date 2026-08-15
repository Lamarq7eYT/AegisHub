import { z } from 'zod';

const timestampSchema = z.string().datetime({ offset: true });
const uuidSchema = z.string().uuid();
const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/i, 'Expected a SHA-256 digest');
const positiveGithubIdSchema = z
  .number()
  .int()
  .positive()
  .refine(Number.isSafeInteger, 'Expected a positive safe integer');
const nonEmptyStringSchema = z.string().min(1);
const statusCodeSchema = z.number().int().min(100).max(599);

export type JsonPrimitive = boolean | null | number | string;
export type JsonObject = { [key: string]: JsonValue };
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];

export function isJsonValue(value: unknown): value is JsonValue {
  return isJsonValueInner(value, new WeakSet<object>());
}

function isJsonValueInner(value: unknown, ancestors: WeakSet<object>): value is JsonValue {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return true;
  }

  if (typeof value === 'number') {
    return Number.isFinite(value);
  }

  if (typeof value !== 'object') {
    return false;
  }

  if (ancestors.has(value) || Object.getOwnPropertySymbols(value).length > 0) {
    return false;
  }

  ancestors.add(value);
  const valid = Array.isArray(value)
    ? isJsonArray(value, ancestors)
    : isJsonObject(value, ancestors);
  ancestors.delete(value);
  return valid;
}

function isJsonArray(value: unknown[], ancestors: WeakSet<object>): boolean {
  if (Object.getPrototypeOf(value) !== Array.prototype) {
    return false;
  }

  const ownNames = Object.getOwnPropertyNames(value);
  if (ownNames.length !== value.length + 1 || ownNames.at(-1) !== 'length') {
    return false;
  }

  for (let index = 0; index < value.length; index += 1) {
    const name = String(index);
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (descriptor?.enumerable !== true || !('value' in descriptor)) {
      return false;
    }
    if (!isJsonValueInner(descriptor.value, ancestors)) {
      return false;
    }
  }

  return true;
}

function isJsonObject(value: object, ancestors: WeakSet<object>): boolean {
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    return false;
  }

  const ownNames = Object.getOwnPropertyNames(value);
  if (ownNames.length !== Object.keys(value).length) {
    return false;
  }

  for (const name of ownNames) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (descriptor?.enumerable !== true || !('value' in descriptor)) {
      return false;
    }
    if (!isJsonValueInner(descriptor.value, ancestors)) {
      return false;
    }
  }

  return true;
}

export const jsonValueSchema = z.custom<JsonValue>(isJsonValue, {
  message: 'Expected a JSON-compatible value'
});

export const actorSchema = z.enum(['owner', 'researcher', 'anonymous']);
export const authenticatedActorSchema = z.enum(['owner', 'researcher']);

export const githubIdentitySchema = z
  .object({
    id: positiveGithubIdSchema,
    nodeId: nonEmptyStringSchema,
    login: nonEmptyStringSchema
  })
  .strict();

export const budgetSchema = z
  .object({
    concurrency: z.number().int().min(1).max(1),
    requestsPerSecond: z.number().positive().max(1),
    burst: z.number().int().min(1).max(2),
    maxRequests: z.number().int().min(1).max(100),
    maxMutations: z.number().int().min(0).max(10),
    timeoutMs: z.number().int().min(1).max(20_000),
    maxReadRetries: z.number().int().min(0).max(2),
    maxMutationRetries: z.literal(0)
  })
  .strict();

export const retentionSchema = z
  .object({
    maxResponseBytes: z.number().int().min(1).max(262_144),
    keepRuns: z.number().int().min(1).max(20)
  })
  .strict();

export const labRepositorySchema = z
  .object({
    id: positiveGithubIdSchema,
    nodeId: nonEmptyStringSchema,
    ownerId: positiveGithubIdSchema,
    owner: nonEmptyStringSchema,
    name: nonEmptyStringSchema,
    fullName: z.string().regex(/^[^/]+\/[^/]+$/, 'Expected exactly one owner/name slash'),
    markerSha256: sha256Schema
  })
  .strict()
  .superRefine((repository, context) => {
    if (repository.fullName !== `${repository.owner}/${repository.name}`) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'fullName must match owner and name',
        path: ['fullName']
      });
    }
  });

export const labManifestSchema = z
  .object({
    schemaVersion: z.literal(1),
    labId: uuidSchema,
    githubHost: z.literal('github.com'),
    owner: githubIdentitySchema,
    researcher: githubIdentitySchema,
    organization: githubIdentitySchema.optional(),
    repositories: z.array(labRepositorySchema),
    approvedOperationFamilies: z.array(nonEmptyStringSchema).min(1),
    budgets: budgetSchema,
    retention: retentionSchema,
    createdAt: timestampSchema,
    verifiedAt: timestampSchema
  })
  .strict()
  .superRefine((manifest, context) => {
    if (manifest.owner.id === manifest.researcher.id) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'owner and researcher must have different GitHub IDs',
        path: ['researcher', 'id']
      });
    }
  });

export const repositoryMarkerSchema = z
  .object({
    schemaVersion: z.literal(1),
    labId: uuidSchema,
    repositoryId: positiveGithubIdSchema,
    ownerId: positiveGithubIdSchema,
    controlNonce: z.string().min(16)
  })
  .strict();

export const policySourceSchema = z
  .object({
    id: nonEmptyStringSchema,
    url: z.string().url(),
    retrievedAt: timestampSchema,
    contentSha256: sha256Schema
  })
  .strict();

export const policySnapshotSchema = z
  .object({
    schemaVersion: z.literal(1),
    policyVersion: nonEmptyStringSchema,
    enforcementSha256: sha256Schema,
    sources: z.array(policySourceSchema).min(1),
    rulesOfEngagement: z.array(nonEmptyStringSchema).min(1),
    inScopeTargets: z.array(nonEmptyStringSchema).min(1),
    ineligibleCategories: z.array(nonEmptyStringSchema).min(1),
    severityReferences: z.array(nonEmptyStringSchema),
    reviewedAt: timestampSchema
  })
  .strict();

export const policySourceStatusSchema = z
  .object({
    sourceId: nonEmptyStringSchema,
    state: z.enum(['match', 'changed', 'unavailable', 'malformed']),
    checkedAt: timestampSchema,
    observedSha256: sha256Schema.optional(),
    malformedReason: z
      .enum([
        'missing-main',
        'multiple-main',
        'malformed-main',
        'empty-normalized-content',
        'invalid-normalized-content',
        'source-too-large',
        'redirect-response',
        'http-error-response'
      ])
      .optional()
  })
  .strict()
  .superRefine((status, context) => {
    if (status.state === 'malformed' && status.malformedReason === undefined) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Malformed policy sources require a malformedReason',
        path: ['malformedReason']
      });
    }
    if (status.state !== 'malformed' && status.malformedReason !== undefined) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Only malformed policy sources may have a malformedReason',
        path: ['malformedReason']
      });
    }
  });

export const policyStatusSchema = z
  .object({
    schemaVersion: z.literal(1),
    policyVersion: nonEmptyStringSchema,
    state: z.enum(['current', 'fresh-unverified', 'stale', 'review-required']),
    checkedAt: timestampSchema,
    sourceStatuses: z.array(policySourceStatusSchema).min(1)
  })
  .strict();

export const operationIdSchema = z
  .string()
  .regex(/^github\.(?:rest|graphql)\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/, 'Invalid operation ID');

const operationParametersSchema = z.record(z.string(), jsonValueSchema);

const baseStepSchema = z
  .object({
    id: nonEmptyStringSchema,
    operationId: operationIdSchema,
    actor: actorSchema,
    repositoryId: positiveGithubIdSchema,
    parameters: operationParametersSchema
  })
  .strict();

export const operationStepSchema = z.discriminatedUnion('phase', [
  baseStepSchema.extend({ phase: z.literal('setup') }).strict(),
  baseStepSchema.extend({ phase: z.literal('baseline') }).strict(),
  baseStepSchema.extend({ phase: z.literal('probe') }).strict(),
  baseStepSchema.extend({ phase: z.literal('verify') }).strict(),
  baseStepSchema.extend({ phase: z.literal('repeat') }).strict(),
  baseStepSchema.extend({ phase: z.literal('cleanup') }).strict()
]);

export const boundaryExpectationSchema = z
  .object({
    kind: z.literal('access-boundary'),
    ownerSuccessStatuses: z.array(z.number().int()).min(1),
    untrustedDeniedStatuses: z.array(z.number().int()).min(1),
    protectedFields: z.array(z.string().min(1)).min(1),
    requireOwnerRepeat: z.literal(true),
    minimumConsistentUntrustedAttempts: z.number().int().min(2).max(3)
  })
  .strict();

export const experimentSchema = z
  .object({
    schemaVersion: z.literal(1),
    id: nonEmptyStringSchema,
    version: z.number().int().min(1),
    title: nonEmptyStringSchema,
    researchQuestion: nonEmptyStringSchema,
    scopeTarget: nonEmptyStringSchema,
    ineligibleCategoryChecks: z.array(nonEmptyStringSchema),
    requiredLabCapabilities: z.array(nonEmptyStringSchema),
    budgets: budgetSchema,
    steps: z.array(operationStepSchema).min(1),
    normalizationProfile: nonEmptyStringSchema,
    expectation: boundaryExpectationSchema,
    expectedSafeOutcome: nonEmptyStringSchema,
    anomalyCondition: nonEmptyStringSchema
  })
  .strict();

export const plannedOperationSchema = z
  .object({
    schemaVersion: z.literal(1),
    planId: uuidSchema,
    plannedAt: timestampSchema,
    labId: uuidSchema,
    experimentId: nonEmptyStringSchema,
    experimentVersion: z.number().int().min(1),
    step: operationStepSchema
  })
  .strict();

export const observationSchema = z
  .object({
    schemaVersion: z.literal(1),
    observationId: uuidSchema,
    runId: uuidSchema,
    experimentId: nonEmptyStringSchema,
    experimentVersion: z.number().int().min(1),
    operationId: operationIdSchema,
    actor: actorSchema,
    repositoryId: positiveGithubIdSchema,
    observedAt: timestampSchema,
    durationMs: z.number().int().min(0),
    method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']),
    endpointTemplate: nonEmptyStringSchema,
    parameters: operationParametersSchema,
    status: statusCodeSchema,
    headers: z.record(z.string(), nonEmptyStringSchema),
    normalizedBody: jsonValueSchema,
    bodySha256: sha256Schema,
    verifiedSideEffect: jsonValueSchema.optional(),
    repeatGroup: nonEmptyStringSchema,
    protectedData: z.boolean(),
    outOfLab: z.boolean(),
    errorClass: nonEmptyStringSchema.optional(),
    policyVersion: nonEmptyStringSchema,
    catalogVersion: nonEmptyStringSchema
  })
  .strict();

export const diffSchema = z
  .object({
    schemaVersion: z.literal(1),
    diffId: uuidSchema,
    runId: uuidSchema,
    experimentId: nonEmptyStringSchema,
    comparedObservationIds: z.array(uuidSchema).min(2),
    outcome: z.enum(['expected', 'anomalous', 'inconclusive']),
    dimensions: z.array(nonEmptyStringSchema).min(1),
    summary: nonEmptyStringSchema,
    details: jsonValueSchema
  })
  .strict();

export const candidateSchema = z
  .object({
    schemaVersion: z.literal(1),
    candidateId: uuidSchema,
    runId: uuidSchema,
    experimentId: nonEmptyStringSchema,
    crossedBoundary: nonEmptyStringSchema,
    reproductionCount: z.number().int().min(2),
    independentlyVerified: z.literal(true),
    knownIneligible: z.literal(false),
    impact: z
      .object({
        kind: z.enum(['confidentiality', 'integrity']),
        summary: nonEmptyStringSchema
      })
      .strict(),
    cleanupStatus: z.literal('complete'),
    evidenceIds: z.array(nonEmptyStringSchema).min(1),
    reproductionSteps: z.array(nonEmptyStringSchema).min(1)
  })
  .strict();

export const runManifestSchema = z
  .object({
    schemaVersion: z.literal(1),
    runId: uuidSchema,
    labId: uuidSchema,
    policyVersion: nonEmptyStringSchema,
    experimentId: nonEmptyStringSchema,
    experimentVersion: z.number().int().min(1),
    startedAt: timestampSchema,
    completedAt: timestampSchema.optional(),
    result: z.enum(['expected', 'anomalous', 'inconclusive', 'policy_blocked', 'dirty']),
    requestCount: z.number().int().min(0),
    mutationCount: z.number().int().min(0),
    cleanupStatus: z.enum(['not-required', 'complete', 'failed', 'manual-resolution-required'])
  })
  .strict();

export const evidenceEntrySchema = z
  .object({
    evidenceId: nonEmptyStringSchema,
    kind: z.enum(['manifest', 'policy', 'experiment', 'plan', 'observation', 'diff', 'candidate', 'report']),
    path: nonEmptyStringSchema,
    sha256: sha256Schema
  })
  .strict();

export const evidenceIndexSchema = z
  .object({
    schemaVersion: z.literal(1),
    runId: uuidSchema,
    generatedAt: timestampSchema,
    entries: z.array(evidenceEntrySchema).min(1)
  })
  .strict();

export const analystObservationSchema = z
  .object({
    schemaVersion: z.literal(1),
    observationId: nonEmptyStringSchema,
    actor: actorSchema,
    status: statusCodeSchema,
    normalizedBody: jsonValueSchema,
    bodySha256: sha256Schema
  })
  .strict();

export const analystInputSchema = z
  .object({
    schemaVersion: z.literal(1),
    labId: uuidSchema,
    runId: uuidSchema,
    evidenceIds: z.array(nonEmptyStringSchema).min(1),
    sanitizedObservations: z.array(analystObservationSchema),
    priorSummaries: z.array(nonEmptyStringSchema),
    policyExcerptIds: z.array(nonEmptyStringSchema).min(1),
    availableOperationIds: z.array(operationIdSchema).min(1)
  })
  .strict();

export const analystHypothesisSchema = z
  .object({
    hypothesis: nonEmptyStringSchema,
    evidenceIds: z.array(nonEmptyStringSchema).min(1)
  })
  .strict();

export const analystOutputSchema = z
  .object({
    schemaVersion: z.literal(1),
    hypotheses: z.array(analystHypothesisSchema),
    benignExplanations: z.array(nonEmptyStringSchema),
    evidenceGaps: z.array(nonEmptyStringSchema),
    suggestedOperationIds: z.array(operationIdSchema),
    suggestedActorArrangements: z.array(z.array(actorSchema).min(1).max(3)),
    confidenceRationale: z
      .object({
        summary: nonEmptyStringSchema,
        evidenceIds: z.array(nonEmptyStringSchema).min(1)
      })
      .strict()
  })
  .strict();

export type Actor = z.infer<typeof actorSchema>;
export type AuthenticatedActor = z.infer<typeof authenticatedActorSchema>;
export type GithubIdentity = z.infer<typeof githubIdentitySchema>;
export type Budget = z.infer<typeof budgetSchema>;
export type Retention = z.infer<typeof retentionSchema>;
export type LabRepository = z.infer<typeof labRepositorySchema>;
export type LabManifest = z.infer<typeof labManifestSchema>;
export type RepositoryMarker = z.infer<typeof repositoryMarkerSchema>;
export type PolicySource = z.infer<typeof policySourceSchema>;
export type PolicySnapshot = z.infer<typeof policySnapshotSchema>;
export type PolicySourceStatus = z.infer<typeof policySourceStatusSchema>;
export type PolicyStatus = z.infer<typeof policyStatusSchema>;
export type OperationId = z.infer<typeof operationIdSchema>;
export type OperationStep = z.infer<typeof operationStepSchema>;
export type BoundaryExpectation = z.infer<typeof boundaryExpectationSchema>;
export type Experiment = z.infer<typeof experimentSchema>;
export type PlannedOperation = z.infer<typeof plannedOperationSchema>;
export type Observation = z.infer<typeof observationSchema>;
export type Diff = z.infer<typeof diffSchema>;
export type Candidate = z.infer<typeof candidateSchema>;
export type RunManifest = z.infer<typeof runManifestSchema>;
export type EvidenceEntry = z.infer<typeof evidenceEntrySchema>;
export type EvidenceIndex = z.infer<typeof evidenceIndexSchema>;
export type AnalystObservation = z.infer<typeof analystObservationSchema>;
export type AnalystInput = z.infer<typeof analystInputSchema>;
export type AnalystHypothesis = z.infer<typeof analystHypothesisSchema>;
export type AnalystOutput = z.infer<typeof analystOutputSchema>;
