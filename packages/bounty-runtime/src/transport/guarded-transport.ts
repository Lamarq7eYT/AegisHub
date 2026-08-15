import { createHash, randomUUID } from 'node:crypto';
import { Buffer } from 'node:buffer';

import {
  observationSchema,
  REPOSITORY_LAB_MARKER_DOCUMENT,
  REPOSITORY_LAB_MARKER_DOCUMENT_ID,
  repositoryMarkerSchema,
  VIEWER_IDENTITY_DOCUMENT,
  VIEWER_IDENTITY_DOCUMENT_ID,
  RunRedactor,
  type Actor,
  type AuthenticatedActor,
  type JsonValue,
  type Observation,
  type PlannedOperation,
  type RepositoryMarker
} from '@aegishub/bounty-core';

import { resolveCatalogOperation, type CatalogExecutionPurpose, type CatalogRepositoryContext } from './operation-catalog.js';
import { RunRateLimiter } from './rate-limiter.js';

export interface GuardedHttpRequest {
  readonly method: string;
  readonly url: globalThis.URL;
  readonly headers: globalThis.Headers;
  readonly redirect: 'manual';
  readonly credentials: 'omit';
  readonly signal: globalThis.AbortSignal;
  readonly body?: string;
}

export interface GuardedHttpResponse {
  readonly status: number;
  readonly headers: Record<string, string | undefined>;
  readonly body: string;
}

export interface LogicalHttpExecutor {
  execute(request: GuardedHttpRequest): Promise<GuardedHttpResponse>;
}

export interface TokenProvider {
  getUsableToken(actor: AuthenticatedActor): Promise<string>;
}

export interface GuardedTransportBudget {
  readonly maxRequests: number;
  readonly maxMutations: number;
}

export interface GuardedTransportContext {
  readonly labId: string;
  readonly runId: string;
  readonly policyVersion: string;
  readonly catalogVersion: string;
  readonly repository: CatalogRepositoryContext;
}

export interface GuardedGitHubTransportOptions {
  readonly executor: LogicalHttpExecutor;
  readonly tokenProvider: TokenProvider;
  readonly rateLimiter: RunRateLimiter;
  readonly budget: GuardedTransportBudget;
  readonly policyFingerprint: () => string;
  readonly expectedPolicyFingerprint: string;
  readonly context: GuardedTransportContext;
  readonly now?: () => Date;
  readonly maxResponseBytes?: number;
}

export type GuardedTransportErrorCode =
  | 'transport_policy_changed'
  | 'transport_budget_exhausted'
  | 'transport_unauthorized'
  | 'transport_rate_limited'
  | 'transport_redirect'
  | 'transport_response_too_large'
  | 'transport_mutation_outcome_unknown'
  | 'transport_network_error'
  | 'transport_upstream_failure'
  | 'transport_invalid_response';

export class GuardedTransportError extends Error {
  constructor(readonly code: GuardedTransportErrorCode) {
    super(code);
    this.name = 'GuardedTransportError';
  }
}

export class GuardedGitHubTransport {
  readonly #options: GuardedGitHubTransportOptions;
  readonly #maxResponseBytes: number;
  readonly #redactor = RunRedactor.create();
  #requestCount = 0;
  #mutationCount = 0;

  constructor(options: GuardedGitHubTransportOptions) {
    this.#options = options;
    this.#maxResponseBytes = options.maxResponseBytes ?? 262_144;
  }

  async execute(request: PlannedOperation, signal: globalThis.AbortSignal): Promise<Observation> {
    const { descriptor, response, startedAt } = await this.executeResponse(request, signal);
    return this.toObservation(request, descriptor.pathTemplate, response, startedAt);
  }

  async readMarker(request: PlannedOperation, signal: globalThis.AbortSignal): Promise<RepositoryMarker | 'missing'> {
    if (request.step.operationId !== 'github.rest.contents.get-lab-marker.v1') {
      throw new GuardedTransportError('transport_invalid_response');
    }
    const { response } = await this.executeResponse(request, signal);
    if (response.status === 404) return 'missing';
    if (response.status !== 200) throw new GuardedTransportError('transport_upstream_failure');
    let parsed: JsonValue;
    try {
      parsed = JSON.parse(response.body) as JsonValue;
    } catch {
      throw new GuardedTransportError('transport_invalid_response');
    }
    const marker = decodeMarkerResponse(parsed);
    if (marker === undefined) throw new GuardedTransportError('transport_invalid_response');
    return marker;
  }

  private async executeResponse(
    request: PlannedOperation,
    signal: globalThis.AbortSignal
  ): Promise<{ descriptor: ReturnType<typeof resolveCatalogOperation>['descriptor']; response: GuardedHttpResponse; startedAt: Date }> {
    if (this.#options.policyFingerprint() !== this.#options.expectedPolicyFingerprint) {
      throw new GuardedTransportError('transport_policy_changed');
    }
    const purpose = purposeForPhase(request.step.phase);
    const resolved = resolveCatalogOperation({
      operationId: request.step.operationId as never,
      parameters: request.step.parameters,
      context: { purpose, actor: request.step.actor, repository: this.#options.context.repository }
    });
    const descriptor = resolved.descriptor;
    const isMutation = descriptor.classification === 'mutation';
    const maxAttempts = descriptor.retry === 'safe-read' ? 3 : 1;
    let lastNetworkError = false;

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      this.reserve(isMutation);
      const startedAt = this.now();
      try {
        const response = await this.#options.rateLimiter.run(
          () => this.send(resolved, request.step.actor, signal),
          signal
        );
        if (response.status >= 300 && response.status < 400) throw new GuardedTransportError('transport_redirect');
        if (response.status === 401) throw new GuardedTransportError('transport_unauthorized');
        if (response.status === 429) throw new GuardedTransportError('transport_rate_limited');
        if (response.status === 403 && (response.headers['x-ratelimit-remaining'] === '0' || /secondary rate limit/iu.test(response.body))) {
          throw new GuardedTransportError('transport_rate_limited');
        }
        if (Buffer.byteLength(response.body, 'utf8') > this.#maxResponseBytes) throw new GuardedTransportError('transport_response_too_large');
        if (response.status >= 500 && response.status <= 599) {
          if (attempt < maxAttempts && !isMutation) continue;
          throw new GuardedTransportError('transport_upstream_failure');
        }
        return { descriptor, response, startedAt };
      } catch (error) {
        if (error instanceof GuardedTransportError) {
          if (error.code === 'transport_upstream_failure' && attempt < maxAttempts && !isMutation) continue;
          throw error;
        }
        lastNetworkError = true;
        if (attempt < maxAttempts && !isMutation) continue;
        throw new GuardedTransportError(isMutation ? 'transport_mutation_outcome_unknown' : 'transport_network_error');
      }
    }
    if (lastNetworkError) throw new GuardedTransportError(isMutation ? 'transport_mutation_outcome_unknown' : 'transport_network_error');
    throw new GuardedTransportError('transport_upstream_failure');
  }

  private reserve(isMutation: boolean): void {
    if (this.#requestCount >= this.#options.budget.maxRequests) {
      throw new GuardedTransportError('transport_budget_exhausted');
    }
    if (isMutation && this.#mutationCount >= this.#options.budget.maxMutations) {
      throw new GuardedTransportError('transport_budget_exhausted');
    }
    this.#requestCount += 1;
    if (isMutation) this.#mutationCount += 1;
  }

  private async send(
    resolved: ReturnType<typeof resolveCatalogOperation>,
    actor: Actor,
    signal: globalThis.AbortSignal
  ): Promise<GuardedHttpResponse> {
    const headers = new globalThis.Headers({
      accept: 'application/vnd.github+json',
      'user-agent': 'aegishub-bounty/0.1',
      'x-github-api-version': '2022-11-28'
    });
    if (resolved.descriptor.protocol === 'graphql' || resolved.descriptor.classification === 'mutation') {
      headers.set('content-type', 'application/json');
    }
    if (actor !== 'anonymous') {
      const token = await this.#options.tokenProvider.getUsableToken(actor);
      headers.set('authorization', `Bearer ${token}`);
    }
    const url = resolved.url ?? new globalThis.URL('https://api.github.com/graphql');
    const response = await this.#options.executor.execute({
      method: resolved.descriptor.method,
      url,
      headers,
      redirect: 'manual',
      credentials: 'omit',
      signal,
      ...(resolved.descriptor.protocol === 'graphql' ? { body: JSON.stringify(graphqlRequestBody(resolved)) } : {}),
      ...(resolved.descriptor.id === 'github.rest.contents.put-lab-marker.v1' || resolved.descriptor.id === 'github.rest.contents.put-lab-boundary-marker.v1' || resolved.descriptor.id === 'github.rest.actions.put-lab-workflow-probe.v1'
        ? { body: JSON.stringify({ message: resolved.parameters.message, content: resolved.parameters.content }) }
        : {}),
      ...(resolved.descriptor.id === 'github.rest.contents.delete-lab-marker.v1' || resolved.descriptor.id === 'github.rest.contents.delete-lab-boundary-marker.v1' || resolved.descriptor.id === 'github.rest.actions.delete-lab-workflow-probe.v1'
        ? { body: JSON.stringify({ message: resolved.parameters.message, sha: resolved.parameters.sha }) }
        : {})
    });
    if (signal.aborted) throw new GuardedTransportError('transport_network_error');
    return response;
  }

  private toObservation(
    request: PlannedOperation,
    endpointTemplate: string,
    response: GuardedHttpResponse,
    startedAt: Date
  ): Observation {
    const rawBytes = Buffer.from(response.body, 'utf8');
    const bodySha256 = createHash('sha256').update(rawBytes).digest('hex');
    let parsed: JsonValue;
    try {
      parsed = JSON.parse(response.body) as JsonValue;
    } catch {
      parsed = this.#redactor.redactText(response.body) as JsonValue;
    }
    const normalizedBody = this.#redactor.redactJson(normalizeMarkerResponse(request.step.operationId, parsed));
    const observedStatus = response.status === 200
      ? statusFromNormalizedGraphqlBody(request.step.operationId, response.status, normalizedBody)
      : response.status;
    const headers: Record<string, string> = {};
    for (const name of ['content-type', 'etag', 'x-github-media-type'] as const) {
      const value = response.headers[name];
      if (value !== undefined) headers[name] = this.#redactor.redactText(value);
    }
    let errorClass: string | undefined;
    if (observedStatus === 403) errorClass = 'access_denied';
    if (observedStatus === 404) errorClass = 'not_found';
    const verifiedSideEffect = request.step.operationId === 'github.rest.contents.put-lab-boundary-marker.v1' && observedStatus >= 200 && observedStatus < 300
      ? { kind: 'repository-content-write', applied: true }
      : request.step.operationId === 'github.rest.actions.put-lab-workflow-probe.v1' && observedStatus >= 200 && observedStatus < 300
        ? { kind: 'workflow-file-write', applied: true }
      : undefined;
    const candidate = {
      schemaVersion: 1,
      observationId: randomUUID(),
      runId: this.#options.context.runId,
      experimentId: request.experimentId,
      experimentVersion: request.experimentVersion,
      operationId: request.step.operationId,
      actor: request.step.actor,
      repositoryId: request.step.repositoryId,
      observedAt: this.now().toISOString(),
      durationMs: Math.max(0, this.now().getTime() - startedAt.getTime()),
      method: this.#methodFor(request),
      endpointTemplate,
      parameters: this.#redactor.redactJson(request.step.parameters),
      status: observedStatus,
      headers,
      normalizedBody,
      bodySha256,
      repeatGroup: request.step.repeatGroup ?? request.step.id,
      protectedData: hasVerifiedLabMarker(normalizedBody, this.#options.context.labId, this.#options.context.repository.id),
      outOfLab: hasOutOfLabRepository(normalizedBody, this.#options.context.repository.id) || hasOutOfLabMarker(normalizedBody, this.#options.context.repository.id),
      ...(verifiedSideEffect === undefined ? {} : { verifiedSideEffect }),
      policyVersion: this.#options.context.policyVersion,
      catalogVersion: this.#options.context.catalogVersion,
      ...(errorClass === undefined ? {} : { errorClass })
    };
    return observationSchema.parse(candidate);
  }

  #methodFor(request: PlannedOperation): 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' {
    const operation = request.step.operationId;
    if (operation.includes('delete')) return 'DELETE';
    if (operation.includes('put')) return 'PUT';
    if (operation.includes('graphql')) return 'POST';
    return 'GET';
  }

  private now(): Date {
    return this.#options.now?.() ?? new Date();
  }
}

function hasVerifiedLabMarker(body: JsonValue, labId: string, repositoryId: number): boolean {
  if (!isJsonObject(body) || !isJsonObject(body.marker)) return false;
  return body.marker.labId === labId && body.marker.repositoryId === repositoryId;
}

function hasOutOfLabRepository(body: JsonValue, repositoryId: number): boolean {
  if (!isJsonObject(body) || !isJsonObject(body.repository)) return false;
  return typeof body.repository.id === 'number' && body.repository.id !== repositoryId;
}

function hasOutOfLabMarker(body: JsonValue, repositoryId: number): boolean {
  if (!isJsonObject(body) || !isJsonObject(body.marker)) return false;
  return typeof body.marker.repositoryId === 'number' && body.marker.repositoryId !== repositoryId;
}

function isJsonObject(value: JsonValue | undefined): value is { readonly [key: string]: JsonValue } {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function normalizeMarkerResponse(operationId: string, body: JsonValue): JsonValue {
  if (operationId === 'github.graphql.contents.get-lab-marker.v1') return normalizeGraphqlMarkerResponse(body);
  if (operationId !== 'github.rest.contents.get-lab-marker.v1') return body;
  const marker = decodeMarkerResponse(body);
  if (marker !== undefined) return markerObservationBody(marker);
  const inlineMarker = decodeInlineMarkerResponse(body);
  return inlineMarker === undefined ? body : { marker: inlineMarker };
}

function markerObservationBody(marker: RepositoryMarker): JsonValue {
  return {
    marker: {
      schemaVersion: marker.schemaVersion,
      labId: marker.labId,
      repositoryId: marker.repositoryId,
      ownerId: marker.ownerId
    }
  };
}

function decodeInlineMarkerResponse(body: JsonValue): { schemaVersion: number; labId: string; repositoryId: number; ownerId?: number } | undefined {
  if (!isJsonObject(body) || !isJsonObject(body.marker)) return undefined;
  const marker = body.marker;
  if (marker.schemaVersion !== 1 || typeof marker.labId !== 'string' || typeof marker.repositoryId !== 'number') return undefined;
  const ownerId = typeof marker.ownerId === 'number'
    ? marker.ownerId
    : isJsonObject(marker.owner) && typeof marker.owner.id === 'number' ? marker.owner.id : undefined;
  return {
    schemaVersion: 1,
    labId: marker.labId,
    repositoryId: marker.repositoryId,
    ...(ownerId === undefined ? {} : { ownerId })
  };
}

function normalizeGraphqlMarkerResponse(body: JsonValue): JsonValue {
  if (!isJsonObject(body)) return {};
  const data = isJsonObject(body.data) ? body.data : undefined;
  const marker = decodeGraphqlMarkerResponse(body);
  const errors = Array.isArray(body.errors) && body.errors.length > 0 ? 'access_denied' : undefined;
  return {
    ...(data?.repository === null ? { repository: null } : {}),
    ...(marker === undefined ? {} : {
      marker: {
        schemaVersion: marker.schemaVersion,
        labId: marker.labId,
        repositoryId: marker.repositoryId,
        ownerId: marker.ownerId
      }
    }),
    ...(errors === undefined ? {} : { errorClass: errors })
  };
}

function decodeGraphqlMarkerResponse(body: JsonValue): RepositoryMarker | undefined {
  if (!isJsonObject(body) || !isJsonObject(body.data) || !isJsonObject(body.data.repository)) return undefined;
  const object = body.data.repository.object;
  if (!isJsonObject(object) || typeof object.text !== 'string') return undefined;
  try {
    const parsed = repositoryMarkerSchema.safeParse(JSON.parse(object.text) as unknown);
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}

function graphqlRequestBody(resolved: ReturnType<typeof resolveCatalogOperation>): Record<string, JsonValue> {
  if (resolved.descriptor.protocol !== 'graphql') throw new GuardedTransportError('transport_invalid_response');
  const variables: Record<string, JsonValue> = {};
  for (const key of resolved.descriptor.parameterKeys) {
    const value = resolved.parameters[key];
    if (value !== undefined) variables[key] = value;
  }
  return {
    operationName: resolved.descriptor.documentId,
    query: graphqlDocument(resolved.descriptor.documentId),
    ...(Object.keys(variables).length === 0 ? {} : { variables })
  };
}

function graphqlDocument(documentId: typeof VIEWER_IDENTITY_DOCUMENT_ID | typeof REPOSITORY_LAB_MARKER_DOCUMENT_ID): string {
  if (documentId === VIEWER_IDENTITY_DOCUMENT_ID) return VIEWER_IDENTITY_DOCUMENT;
  if (documentId === REPOSITORY_LAB_MARKER_DOCUMENT_ID) return REPOSITORY_LAB_MARKER_DOCUMENT;
  throw new GuardedTransportError('transport_invalid_response');
}

function statusFromNormalizedGraphqlBody(operationId: string, status: number, body: JsonValue): number {
  if (operationId !== 'github.graphql.contents.get-lab-marker.v1') return status;
  if (!isJsonObject(body)) return status;
  if (body.errorClass === 'access_denied') return 403;
  if (body.repository === null || (!('marker' in body) && isJsonObject(body.repository) && Object.keys(body.repository).length === 0)) return 404;
  return status;
}

function decodeMarkerResponse(body: JsonValue): RepositoryMarker | undefined {
  if (!isJsonObject(body) || body.encoding !== 'base64' || typeof body.content !== 'string') return undefined;
  const compactContent = body.content.replace(/\s/gu, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/u.test(compactContent)) return undefined;
  try {
    const decoded = Buffer.from(compactContent, 'base64').toString('utf8');
    const parsed = repositoryMarkerSchema.safeParse(JSON.parse(decoded) as unknown);
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}

function purposeForPhase(phase: PlannedOperation['step']['phase']): CatalogExecutionPurpose {
  if (phase === 'cleanup') return 'cleanup';
  if (phase === 'setup') return 'enrollment';
  return 'experiment';
}
