import { describe, expect, it } from 'vitest';

import {
  analystInputSchema,
  analystOutputSchema,
  type AnalystInput,
  type AnalystObservation
} from '../src/contracts.js';
import { buildAnalysisPack } from '../src/analysis-pack.js';

const validObservation: AnalystObservation = {
  schemaVersion: 1,
  observationId: 'obs-0001',
  actor: 'researcher',
  status: 404,
  normalizedBody: { denied: true },
  bodySha256: 'a'.repeat(64)
};

const validInput: AnalystInput = {
  schemaVersion: 1,
  labId: '95f38cca-42e2-4b7d-82e6-f13f4549b2f3',
  runId: 'c5d4e3f2-a1b0-4987-8765-43210fedcba9',
  evidenceIds: ['obs-0001'],
  sanitizedObservations: [validObservation],
  priorSummaries: ['The untrusted actor received a documented denial.'],
  policyExcerptIds: ['scope.read-boundary'],
  availableOperationIds: ['github.rest.contents.get-lab-marker.v1']
};

const validOutput = {
  schemaVersion: 1 as const,
  hypotheses: [
    {
      hypothesis: 'The denial is consistent with the declared boundary.',
      evidenceIds: ['obs-0001']
    }
  ],
  benignExplanations: ['The repository is private.'],
  evidenceGaps: [],
  suggestedOperationIds: ['github.rest.contents.get-lab-marker.v1'],
  suggestedActorArrangements: [['owner', 'researcher']],
  confidenceRationale: {
    summary: 'The hypothesis cites the sanitized observation.',
    evidenceIds: ['obs-0001']
  }
};

describe('buildAnalysisPack', () => {
  it('accepts only schema-valid sanitized observations and freezes the result', () => {
    const pack = buildAnalysisPack(validInput);

    expect(analystInputSchema.safeParse(pack).success).toBe(true);
    expect(pack).toEqual(validInput);
    expect(Object.isFrozen(pack)).toBe(true);
    expect(Object.isFrozen(pack.sanitizedObservations)).toBe(true);
  });

  it.each([
    ['url', { url: 'https://api.github.com/repos/fixture' }],
    ['method', { method: 'GET' }],
    ['headers', { headers: { authorization: 'fixture-token' } }],
    ['GraphQL', { graphql: 'query Fixture { viewer { login } }' }],
    ['code', { code: 'fetch("https://fixture")' }],
    ['script', { script: 'process.exit(1)' }],
    ['command', { command: 'curl https://fixture' }],
    ['approval', { approval: true }],
    ['token', { token: 'ghp_fixture_token_1234567890' }],
    ['raw body', { rawBody: 'raw fixture response' }]
  ] as const)('rejects an executable or credential-shaped %s field', (_label, field) => {
    expect(() => buildAnalysisPack({ ...validInput, ...field } as never)).toThrow(
      'invalid_analysis_pack'
    );
  });

  it.each([
    ['method', { method: 'GET' }],
    ['headers', { headers: {} }],
    ['url', { url: 'https://fixture' }],
    ['raw body', { rawBody: { secret: 'fixture' } }],
    ['token', { token: 'ghp_fixture_token_1234567890' }]
  ] as const)('rejects forbidden fields inside sanitized observations: %s', (_label, field) => {
    expect(() =>
      buildAnalysisPack({
        ...validInput,
        sanitizedObservations: [{ ...validObservation, ...field }]
      } as never)
    ).toThrow('invalid_analysis_pack');
  });
});

describe('analystOutputSchema', () => {
  it('accepts hypotheses that cite evidence and existing operation IDs', () => {
    expect(analystOutputSchema.safeParse(validOutput).success).toBe(true);
  });

  it.each([
    ['url', { url: 'https://fixture' }],
    ['method', { method: 'GET' }],
    ['headers', { headers: {} }],
    ['GraphQL', { graphql: 'query Fixture { viewer { login } }' }],
    ['code', { code: 'return fetch("https://fixture")' }],
    ['script', { script: 'console.log("fixture")' }],
    ['command', { command: 'curl https://fixture' }],
    ['approval', { approval: true }],
    ['token', { token: 'ghp_fixture_token_1234567890' }],
    ['raw body', { rawBody: 'fixture body' }]
  ] as const)('rejects a forbidden output field: %s', (_label, field) => {
    expect(analystOutputSchema.safeParse({ ...validOutput, ...field }).success).toBe(false);
  });
});
