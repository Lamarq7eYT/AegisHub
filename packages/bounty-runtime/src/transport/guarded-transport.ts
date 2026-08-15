import { createHash, randomUUID } from 'node:crypto';
import { Buffer } from 'node:buffer';

import {
  observationSchema,
  RunRedactor,
  type Actor,
  type AuthenticatedActor,
  type JsonValue,
  type Observation,
  type PlannedOperation
} from '@aegishub/bounty-core';

import { resolveCatalogOperation, type CatalogExecutionPurpose, type CatalogRepositoryContext } from './operation-catalog.js';
import { RunRateLimiter } from './rate-limiter.js';

export interface GuardedHttpRequest {
  readonly method: string;
  readonly url: globalThis.URL;
  readonly headers: globalThis.Headers;
  readonly redirect: 'manual';
  readonly credentials: 'omit';
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
        if (response.status >= 300 && response.status < 400) {
          throw new GuardedTransportError('transport_redirect');
        }
        if (response.status === 401) throw new GuardedTransportError('transport_unauthorized');
        if (response.status === 429) throw new GuardedTransportError('transport_rate_limited');
        if (Buffer.byteLength(response.body, 'utf8') > this.#maxResponseBytes) {
          throw new GuardedTransportError('transport_response_too_large');
        }
        if (response.status >= 500 && response.status <= 599) {
          if (attempt < maxAttempts && !isMutation) continue;
          throw new GuardedTransportError('transport_upstream_failure');
        }
        return this.toObservation(request, descriptor.pathTemplate, response, startedAt);
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
      ...(resolved.descriptor.protocol === 'graphql' ? { body: JSON.stringify({ documentId: 'ViewerIdentityV1' }) } : {})
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
    const normalizedBody = this.#redactor.redactJson(parsed);
    const headers: Record<string, string> = {};
    for (const name of ['content-type', 'etag', 'x-github-media-type'] as const) {
      const value = response.headers[name];
      if (value !== undefined) headers[name] = this.#redactor.redactText(value);
    }
    let errorClass: string | undefined;
    if (response.status === 403) errorClass = 'access_denied';
    if (response.status === 404) errorClass = 'not_found';
    const candidate = {
      schemaVersion: 1,
      observationId: randomUUID(),
      runId: request.planId,
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
      status: response.status,
      headers,
      normalizedBody,
      bodySha256,
      repeatGroup: request.step.id,
      protectedData: false,
      outOfLab: false,
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

function purposeForPhase(phase: PlannedOperation['step']['phase']): CatalogExecutionPurpose {
  if (phase === 'cleanup') return 'cleanup';
  if (phase === 'setup') return 'enrollment';
  return 'experiment';
}
