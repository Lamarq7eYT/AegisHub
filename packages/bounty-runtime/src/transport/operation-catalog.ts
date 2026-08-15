import {
  getOperationDescriptor,
  isExperimentOperation,
  renderRestUrl,
  validateOperationParameters,
  type Actor,
  type JsonValue,
  type OperationDescriptor,
  type CatalogOperationId
} from '@aegishub/bounty-core';

export type CatalogExecutionPurpose = 'identity' | 'enrollment' | 'experiment' | 'cleanup';

export interface CatalogRepositoryContext {
  readonly id: number;
  readonly nodeId: string;
  readonly fullName: string;
}

export interface CatalogExecutionContext {
  readonly purpose: CatalogExecutionPurpose;
  readonly actor: Actor;
  readonly repository: CatalogRepositoryContext;
}

export interface ResolveCatalogOperationInput {
  readonly operationId: CatalogOperationId;
  readonly parameters: unknown;
  readonly context: CatalogExecutionContext;
}

export interface ResolvedCatalogOperation {
  readonly descriptor: OperationDescriptor;
  readonly parameters: Record<string, JsonValue>;
  readonly context: CatalogExecutionContext;
  readonly url?: globalThis.URL;
}

export class CatalogRuntimeError extends Error {
  constructor(readonly code: 'catalog_unknown_operation' | 'catalog_invalid_parameters' | 'catalog_purpose_denied' | 'catalog_actor_denied' | 'catalog_repository_mismatch') {
    super(code);
    this.name = 'CatalogRuntimeError';
  }
}

export function resolveCatalogOperation(input: ResolveCatalogOperationInput): ResolvedCatalogOperation {
  let descriptor: OperationDescriptor;
  try {
    descriptor = getOperationDescriptor(input.operationId);
  } catch {
    throw new CatalogRuntimeError('catalog_unknown_operation');
  }
  if (!descriptor.purpose.includes(input.context.purpose)) {
    throw new CatalogRuntimeError('catalog_purpose_denied');
  }
  if (!descriptor.allowedActors.includes(input.context.actor)) {
    throw new CatalogRuntimeError('catalog_actor_denied');
  }
  let parameters: Record<string, JsonValue>;
  try {
    parameters = validateOperationParameters(input.operationId, input.parameters);
  } catch {
    throw new CatalogRuntimeError('catalog_invalid_parameters');
  }
  if (descriptor.parameterKeys.includes('owner')) {
    try {
      const expected = descriptor.protocol === 'rest'
        ? (() => {
          const url = renderRestUrl(input.operationId, parameters);
          return `${url.pathname.split('/')[2]}/${url.pathname.split('/')[3]}`;
        })()
        : `${parameters.owner}/${parameters.repo}`;
      if (decodeURIComponent(expected) !== input.context.repository.fullName) {
        throw new CatalogRuntimeError('catalog_repository_mismatch');
      }
    } catch (error) {
      if (error instanceof CatalogRuntimeError) throw error;
      throw new CatalogRuntimeError('catalog_invalid_parameters');
    }
  }
  if (input.context.purpose === 'experiment' && !isExperimentOperation(input.operationId)) {
    throw new CatalogRuntimeError('catalog_purpose_denied');
  }
  return Object.freeze({
    descriptor,
    parameters: Object.freeze(parameters),
    context: input.context,
    ...(descriptor.protocol === 'rest' ? { url: renderRestUrl(input.operationId, parameters) } : {})
  });
}
