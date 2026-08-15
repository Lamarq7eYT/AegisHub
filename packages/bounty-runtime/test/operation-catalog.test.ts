import { describe, expect, it } from 'vitest';

import {
  CatalogRuntimeError,
  resolveCatalogOperation,
  type CatalogExecutionContext
} from '../src/transport/operation-catalog.js';

const repository = {
  id: 3003,
  nodeId: 'R_lab_fixture',
  fullName: 'owner-fixture/lab-fixture'
} as const;

const context = (purpose: CatalogExecutionContext['purpose'], actor: CatalogExecutionContext['actor']): CatalogExecutionContext => ({
  purpose,
  actor,
  repository
});

describe('runtime operation catalog', () => {
  it('permits only experiment-visible operations in experiment context', () => {
    expect(resolveCatalogOperation({
      operationId: 'github.rest.repos.get.v1',
      parameters: { owner: 'owner-fixture', repo: 'lab-fixture' },
      context: context('experiment', 'anonymous')
    }).descriptor.id).toBe('github.rest.repos.get.v1');

    expect(() => resolveCatalogOperation({
      operationId: 'github.rest.users.get-authenticated.v1',
      parameters: {},
      context: context('experiment', 'owner')
    })).toThrowError(new CatalogRuntimeError('catalog_purpose_denied'));
  });

  it('requires the actor allowlist and protects mutation operations', () => {
    expect(() => resolveCatalogOperation({
      operationId: 'github.rest.contents.put-lab-marker.v1',
      parameters: { owner: 'owner-fixture', repo: 'lab-fixture', message: 'aegishub: verify bounty lab', content: 'e30=' },
      context: context('enrollment', 'researcher')
    })).toThrowError(new CatalogRuntimeError('catalog_actor_denied'));

    expect(resolveCatalogOperation({
      operationId: 'github.rest.contents.put-lab-marker.v1',
      parameters: { owner: 'owner-fixture', repo: 'lab-fixture', message: 'aegishub: verify bounty lab', content: 'e30=' },
      context: context('enrollment', 'owner')
    }).descriptor.classification).toBe('mutation');
  });

  it('defines the private-content boundary mutation as a fixed experiment operation with owner-only cleanup', () => {
    const parameters = { owner: 'owner-fixture', repo: 'lab-fixture', message: 'aegishub: verify bounty lab', content: 'e30=' };
    expect(resolveCatalogOperation({
      operationId: 'github.rest.contents.put-lab-boundary-marker.v1' as never,
      parameters,
      context: context('experiment', 'researcher')
    }).descriptor.classification).toBe('mutation');
    expect(resolveCatalogOperation({
      operationId: 'github.rest.contents.delete-lab-boundary-marker.v1' as never,
      parameters: { owner: 'owner-fixture', repo: 'lab-fixture', message: 'aegishub: remove bounty lab marker', sha: 'fixture-sha' },
      context: context('cleanup', 'owner')
    }).descriptor.allowedActors).toEqual(['owner']);
  });

  it('pins the logical repository identity and rejects a name-only or mismatched request', () => {
    expect(() => resolveCatalogOperation({
      operationId: 'github.rest.repos.get.v1',
      parameters: { owner: 'other', repo: 'lab-fixture' },
      context: context('enrollment', 'owner')
    })).toThrowError(new CatalogRuntimeError('catalog_repository_mismatch'));

    const resolved = resolveCatalogOperation({
      operationId: 'github.rest.repos.get.v1',
      parameters: { owner: 'owner-fixture', repo: 'lab-fixture' },
      context: { purpose: 'enrollment', actor: 'owner', repository: { id: 3003, nodeId: 'R_other', fullName: repository.fullName } }
    });
    expect(resolved.context.repository.nodeId).toBe('R_other');
  });
});
