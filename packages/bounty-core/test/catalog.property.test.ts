import { describe, expect, it } from 'vitest';
import fc from 'fast-check';

import {
  CATALOG_VERSION,
  OPERATION_CATALOG,
  catalogFingerprint,
  getOperationDescriptor,
  renderRestUrl,
  type OperationDescriptor,
  type CatalogOperationId
} from '../src/catalog.js';

const restId: CatalogOperationId = 'github.rest.repos.get.v1';

describe('operation catalog', () => {
  it('renders repository parameters only inside encoded path segments at the fixed origin', () => {
    fc.assert(
      fc.property(fc.string({ minLength: 1 }), fc.string({ minLength: 1 }), (owner, repo) => {
        try {
          const url = renderRestUrl(restId, { owner, repo });
          expect(url.origin).toBe('https://api.github.com');
          expect(url.search).toBe('');
          expect(url.hash).toBe('');
          expect(url.pathname.startsWith('/repos/')).toBe(true);
          if (owner !== '.' && owner !== '..' && repo !== '.' && repo !== '..') {
            expect(decodeURIComponent(url.pathname)).toContain(`/repos/${owner}/${repo}`);
          }
        } catch {
          expect(['.', '..']).toContain(owner === '.' || owner === '..' ? owner : repo);
        }
      }),
      { numRuns: 100 }
    );
  });

  it('keeps experiment-visible operations separate from identity, enrollment, and cleanup-only operations', () => {
    const visible = Object.values(OPERATION_CATALOG).filter((descriptor) => descriptor.purpose.includes('experiment'));
    expect(visible.map(({ id }) => id)).toEqual([
      'github.rest.repos.get.v1',
      'github.rest.contents.get-lab-marker.v1',
      'github.graphql.contents.get-lab-marker.v1'
    ]);
    expect(visible.every(({ purpose }) => !purpose.includes('identity') || purpose.includes('experiment'))).toBe(true);
    expect(Object.values(OPERATION_CATALOG).some(({ purpose }) => purpose.includes('cleanup') && !purpose.includes('experiment'))).toBe(true);
  });

  it('selects a checked-in GraphQL document ID rather than accepting query text', () => {
    const descriptor = getOperationDescriptor('github.graphql.viewer-identity.v1');
    expect(descriptor.protocol).toBe('graphql');
    expect(descriptor).toMatchObject({ documentId: 'ViewerIdentityV1' });
    expect('query' in descriptor).toBe(false);
  });

  it('exposes only the fixed GraphQL lab-marker document and typed repository parameters', () => {
    const descriptor = getOperationDescriptor('github.graphql.contents.get-lab-marker.v1');
    expect(descriptor).toMatchObject({
      protocol: 'graphql',
      documentId: 'RepositoryLabMarkerV1',
      pathTemplate: '/graphql',
      parameterKeys: ['owner', 'repo']
    });
    expect('query' in descriptor).toBe(false);
  });

  it('changes the catalog fingerprint when any descriptor field changes', () => {
    const original = catalogFingerprint(OPERATION_CATALOG);
    const changed = {
      ...OPERATION_CATALOG,
      [restId]: {
        ...OPERATION_CATALOG[restId],
        retainedFields: [...OPERATION_CATALOG[restId].retainedFields, 'fixture-change']
      }
    } satisfies Readonly<Record<CatalogOperationId, OperationDescriptor>>;
    expect(original).not.toBe(catalogFingerprint(changed));
    expect(CATALOG_VERSION).toBe('1.1.0');
  });

  it('rejects unknown operation IDs and parameter fields', () => {
    expect(() => getOperationDescriptor('github.rest.unknown.v1' as CatalogOperationId)).toThrow();
    expect(() => renderRestUrl(restId, { owner: 'owner', repo: 'repo', query: 'x' } as never)).toThrow();
  });
});
