import { z } from 'zod';

import { sha256StableJson } from './stable-json.js';
import type { Actor, JsonValue } from './contracts.js';

export const CATALOG_VERSION = '1.1.0' as const;
export const VIEWER_IDENTITY_DOCUMENT_ID = 'ViewerIdentityV1' as const;
export const VIEWER_IDENTITY_DOCUMENT = `query ViewerIdentityV1 {
  viewer {
    databaseId
    id
    login
  }
}` as const;
export const REPOSITORY_LAB_MARKER_DOCUMENT_ID = 'RepositoryLabMarkerV1' as const;
export const REPOSITORY_LAB_MARKER_DOCUMENT = `query RepositoryLabMarkerV1($owner: String!, $repo: String!) {
  repository(owner: $owner, name: $repo) {
    databaseId
    isPrivate
    object(expression: "HEAD:.aegishub-lab.json") {
      ... on Blob {
        text
      }
    }
  }
}` as const;

type OperationId =
  | 'github.rest.users.get-authenticated.v1'
  | 'github.graphql.viewer-identity.v1'
  | 'github.graphql.contents.get-lab-marker.v1'
  | 'github.rest.repos.get.v1'
  | 'github.rest.contents.get-lab-marker.v1'
  | 'github.rest.contents.put-lab-marker.v1'
  | 'github.rest.contents.delete-lab-marker.v1';

export type CatalogOperationId = OperationId;

export type OperationPurpose = 'identity' | 'enrollment' | 'experiment' | 'cleanup';
export type OperationClassification = 'read' | 'mutation';
export type OperationPermission = 'metadata:read' | 'contents:read' | 'contents:write';
export type OperationRetry = 'safe-read' | 'never';
export type RetainedResponseHeader = 'content-type' | 'etag' | 'x-github-media-type';

interface OperationDescriptorBase {
  readonly id: OperationId;
  readonly version: 1;
  readonly purpose: readonly OperationPurpose[];
  readonly classification: OperationClassification;
  readonly allowedActors: readonly Actor[];
  readonly permission: OperationPermission;
  readonly retry: OperationRetry;
  readonly cleanupOperationId?: OperationId;
  readonly normalizationProfile: string;
  readonly retainedResponseHeaders: readonly RetainedResponseHeader[];
  readonly retainedFields: readonly string[];
  readonly parameterKeys: readonly string[];
}

export interface RestOperationDescriptor extends OperationDescriptorBase {
  readonly protocol: 'rest';
  readonly method: 'GET' | 'PUT' | 'DELETE';
  readonly pathTemplate: string;
}

export interface GraphqlOperationDescriptor extends OperationDescriptorBase {
  readonly protocol: 'graphql';
  readonly method: 'POST';
  readonly pathTemplate: '/graphql';
  readonly documentId: typeof VIEWER_IDENTITY_DOCUMENT_ID | typeof REPOSITORY_LAB_MARKER_DOCUMENT_ID;
}

export type OperationDescriptor = RestOperationDescriptor | GraphqlOperationDescriptor;
export type OperationCatalog = Readonly<Record<OperationId, OperationDescriptor>>;

const allActors: readonly Actor[] = Object.freeze(['owner', 'researcher', 'anonymous']);
const authenticatedActors: readonly Actor[] = Object.freeze(['owner', 'researcher']);
const repositoryParametersSchema = z.object({ owner: z.string().min(1), repo: z.string().min(1) }).strict();
const markerPutParametersSchema = z.object({
  owner: z.string().min(1),
  repo: z.string().min(1),
  message: z.literal('aegishub: verify bounty lab'),
  content: z.string().min(1).max(1_000_000).regex(/^[A-Za-z0-9+/]+={0,2}$/u)
}).strict();
const markerDeleteParametersSchema = z.object({
  owner: z.string().min(1),
  repo: z.string().min(1),
  message: z.literal('aegishub: remove bounty lab marker'),
  sha: z.string().min(1).max(200).regex(/^[A-Za-z0-9_-]+$/u)
}).strict();
const emptyParametersSchema = z.object({}).strict();
const parameterSchemas: Readonly<Record<OperationId, z.ZodType<Record<string, JsonValue>>>> = {
  'github.rest.users.get-authenticated.v1': emptyParametersSchema,
  'github.graphql.viewer-identity.v1': emptyParametersSchema,
  'github.rest.repos.get.v1': repositoryParametersSchema,
  'github.rest.contents.get-lab-marker.v1': repositoryParametersSchema,
  'github.graphql.contents.get-lab-marker.v1': repositoryParametersSchema,
  'github.rest.contents.put-lab-marker.v1': markerPutParametersSchema,
  'github.rest.contents.delete-lab-marker.v1': markerDeleteParametersSchema
};

const descriptors: Record<OperationId, OperationDescriptor> = {
  'github.rest.users.get-authenticated.v1': {
    id: 'github.rest.users.get-authenticated.v1',
    version: 1,
    protocol: 'rest',
    method: 'GET',
    pathTemplate: '/user',
    purpose: ['identity'],
    classification: 'read',
    allowedActors: authenticatedActors,
    permission: 'metadata:read',
    retry: 'safe-read',
    normalizationProfile: 'authenticated-user-v1',
    retainedResponseHeaders: ['content-type', 'etag', 'x-github-media-type'],
    retainedFields: ['id', 'node_id', 'login'],
    parameterKeys: []
  },
  'github.graphql.viewer-identity.v1': {
    id: 'github.graphql.viewer-identity.v1',
    version: 1,
    protocol: 'graphql',
    method: 'POST',
    pathTemplate: '/graphql',
    documentId: VIEWER_IDENTITY_DOCUMENT_ID,
    purpose: ['identity'],
    classification: 'read',
    allowedActors: authenticatedActors,
    permission: 'metadata:read',
    retry: 'safe-read',
    normalizationProfile: 'viewer-identity-v1',
    retainedResponseHeaders: ['content-type', 'etag', 'x-github-media-type'],
    retainedFields: ['databaseId', 'id', 'login'],
    parameterKeys: []
  },
  'github.rest.repos.get.v1': {
    id: 'github.rest.repos.get.v1',
    version: 1,
    protocol: 'rest',
    method: 'GET',
    pathTemplate: '/repos/{owner}/{repo}',
    purpose: ['enrollment', 'experiment'],
    classification: 'read',
    allowedActors: allActors,
    permission: 'metadata:read',
    retry: 'safe-read',
    normalizationProfile: 'repository-v1',
    retainedResponseHeaders: ['content-type', 'etag', 'x-github-media-type'],
    retainedFields: ['id', 'node_id', 'full_name', 'owner', 'private', 'visibility', 'default_branch'],
    parameterKeys: ['owner', 'repo']
  },
  'github.rest.contents.get-lab-marker.v1': {
    id: 'github.rest.contents.get-lab-marker.v1',
    version: 1,
    protocol: 'rest',
    method: 'GET',
    pathTemplate: '/repos/{owner}/{repo}/contents/.aegishub-lab.json',
    purpose: ['enrollment', 'experiment', 'cleanup'],
    classification: 'read',
    allowedActors: allActors,
    permission: 'contents:read',
    retry: 'safe-read',
    normalizationProfile: 'marker-read-v1',
    retainedResponseHeaders: ['content-type', 'etag', 'x-github-media-type'],
    retainedFields: ['sha', 'marker'],
    parameterKeys: ['owner', 'repo']
  },
  'github.graphql.contents.get-lab-marker.v1': {
    id: 'github.graphql.contents.get-lab-marker.v1',
    version: 1,
    protocol: 'graphql',
    method: 'POST',
    pathTemplate: '/graphql',
    documentId: REPOSITORY_LAB_MARKER_DOCUMENT_ID,
    purpose: ['experiment'],
    classification: 'read',
    allowedActors: allActors,
    permission: 'contents:read',
    retry: 'safe-read',
    normalizationProfile: 'marker-read-v1',
    retainedResponseHeaders: ['content-type', 'etag', 'x-github-media-type'],
    retainedFields: ['repository.databaseId', 'repository.isPrivate', 'repository.object.text'],
    parameterKeys: ['owner', 'repo']
  },
  'github.rest.contents.put-lab-marker.v1': {
    id: 'github.rest.contents.put-lab-marker.v1',
    version: 1,
    protocol: 'rest',
    method: 'PUT',
    pathTemplate: '/repos/{owner}/{repo}/contents/.aegishub-lab.json',
    purpose: ['enrollment'],
    classification: 'mutation',
    allowedActors: ['owner'],
    permission: 'contents:write',
    retry: 'never',
    cleanupOperationId: 'github.rest.contents.delete-lab-marker.v1',
    normalizationProfile: 'marker-mutation-v1',
    retainedResponseHeaders: ['content-type', 'etag', 'x-github-media-type'],
    retainedFields: ['content.sha', 'commit.sha'],
    parameterKeys: ['owner', 'repo']
  },
  'github.rest.contents.delete-lab-marker.v1': {
    id: 'github.rest.contents.delete-lab-marker.v1',
    version: 1,
    protocol: 'rest',
    method: 'DELETE',
    pathTemplate: '/repos/{owner}/{repo}/contents/.aegishub-lab.json',
    purpose: ['cleanup'],
    classification: 'mutation',
    allowedActors: ['owner'],
    permission: 'contents:write',
    retry: 'never',
    normalizationProfile: 'marker-mutation-v1',
    retainedResponseHeaders: ['content-type', 'etag', 'x-github-media-type'],
    retainedFields: ['content.sha', 'commit.sha'],
    parameterKeys: ['owner', 'repo']
  }
};

export const OPERATION_CATALOG: OperationCatalog = Object.freeze(
  Object.fromEntries(Object.entries(descriptors).map(([id, descriptor]) => [id, Object.freeze({ ...descriptor })]))
) as OperationCatalog;

export function getOperationDescriptor(id: OperationId): OperationDescriptor {
  const descriptor = OPERATION_CATALOG[id];
  if (descriptor === undefined) throw new Error('catalog_unknown_operation');
  return descriptor;
}

export function validateOperationParameters(id: OperationId, parameters: unknown): Record<string, JsonValue> {
  const descriptor = getOperationDescriptor(id);
  const parsed = parameterSchemas[descriptor.id].safeParse(parameters);
  if (!parsed.success) throw new Error('catalog_invalid_parameters');
  return parsed.data;
}

export function renderRestUrl(id: OperationId, parameters: unknown): globalThis.URL {
  const descriptor = getOperationDescriptor(id);
  if (descriptor.protocol !== 'rest') throw new Error('catalog_not_rest_operation');
  const validated = validateOperationParameters(id, parameters);
  let path = descriptor.pathTemplate;
  for (const key of descriptor.parameterKeys) {
    const value = validated[key];
    if (typeof value !== 'string' || value === '.' || value === '..') throw new Error('catalog_invalid_parameters');
    path = path.replace(`{${key}}`, encodeURIComponent(value));
  }
  if (path.includes('{') || path.includes('}') || path.includes('?') || path.includes('#')) {
    throw new Error('catalog_invalid_rendered_path');
  }
  return new globalThis.URL(`https://api.github.com${path}`);
}

export function catalogFingerprint(catalog: OperationCatalog): string {
  const serializable = Object.fromEntries(
    (Object.keys(catalog) as OperationId[]).sort().map((id) => {
      const descriptor = catalog[id];
      return [id, descriptor];
    })
  );
  return sha256StableJson(serializable as unknown as JsonValue);
}

export function isExperimentOperation(id: OperationId): boolean {
  return getOperationDescriptor(id).purpose.includes('experiment');
}
