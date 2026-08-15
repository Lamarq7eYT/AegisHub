import { mkdir, mkdtemp, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';
import { sha256StableJson, type Experiment } from '@aegishub/bounty-core';

import { ExperimentLoader, ExperimentLoaderError } from '../src/experiments/loader.js';

function experiment(overrides: Partial<Experiment> = {}): Experiment {
  return {
    schemaVersion: 1,
    id: 'bundled-access-boundary-v1',
    version: 1,
    title: 'Fixture access boundary',
    researchQuestion: 'Does an untrusted actor remain denied?',
    scopeTarget: 'owner-fixture/lab-fixture',
    ineligibleCategoryChecks: ['no credential attack'],
    requiredLabCapabilities: ['private-repository'],
    budgets: {
      concurrency: 1,
      requestsPerSecond: 1,
      burst: 2,
      maxRequests: 10,
      maxMutations: 0,
      timeoutMs: 20_000,
      maxReadRetries: 2,
      maxMutationRetries: 0
    },
    steps: [
      {
        phase: 'baseline',
        id: 'read-repository',
        operationId: 'github.rest.repos.get.v1',
        actor: 'anonymous',
        repositoryId: 3003,
        parameters: { owner: 'owner-fixture', repo: 'lab-fixture' }
      }
    ],
    normalizationProfile: 'repository-v1',
    expectation: {
      kind: 'access-boundary',
      ownerSuccessStatuses: [200],
      untrustedDeniedStatuses: [403, 404],
      protectedFields: ['private'],
      requireOwnerRepeat: true,
      minimumConsistentUntrustedAttempts: 2
    },
    expectedSafeOutcome: 'untrusted access is denied',
    anomalyCondition: 'untrusted access succeeds',
    ...overrides
  };
}

function yamlExperiment(): string {
  return `schemaVersion: 1
id: bundled-access-boundary-v1
version: 1
title: Fixture access boundary
researchQuestion: Does an untrusted actor remain denied?
scopeTarget: owner-fixture/lab-fixture
ineligibleCategoryChecks:
  - no credential attack
requiredLabCapabilities:
  - private-repository
budgets:
  concurrency: 1
  requestsPerSecond: 1
  burst: 2
  maxRequests: 10
  maxMutations: 0
  timeoutMs: 20000
  maxReadRetries: 2
  maxMutationRetries: 0
steps:
  - phase: baseline
    id: read-repository
    operationId: github.rest.repos.get.v1
    actor: anonymous
    repositoryId: 3003
    parameters:
      owner: owner-fixture
      repo: lab-fixture
normalizationProfile: repository-v1
expectation:
  kind: access-boundary
  ownerSuccessStatuses: [200]
  untrustedDeniedStatuses: [403, 404]
  protectedFields: [private]
  requireOwnerRepeat: true
  minimumConsistentUntrustedAttempts: 2
expectedSafeOutcome: untrusted access is denied
anomalyCondition: untrusted access succeeds
`;
}

describe('ExperimentLoader', () => {
  it('accepts strict YAML and equivalent JSON with identical stable hash', async () => {
    const workspace = await mkdtemp(join(tmpdir(), 'aegishub-experiment-loader-'));
    const directory = join(workspace, '.aegishub', 'experiments');
    await mkdir(directory, { recursive: true });
    const yamlPath = join(directory, 'fixture.yaml');
    const jsonPath = join(directory, 'fixture.json');
    await writeFile(yamlPath, yamlExperiment());
    await writeFile(jsonPath, JSON.stringify(experiment()));
    const loader = new ExperimentLoader({ workspaceRoot: workspace, runtimeRoot: workspace });

    const yaml = await loader.load(yamlPath);
    const json = await loader.load(jsonPath);

    expect(yaml.experiment).toEqual(json.experiment);
    expect(yaml.sha256).toBe(json.sha256);
    expect(yaml.sha256).toBe(sha256StableJson(experiment()));
  });

  it.each([
    ['oversized file', 'x'.repeat(65_537), 'experiment_too_large'],
    ['unknown field', JSON.stringify({ ...experiment(), unknown: true }), 'invalid_experiment'],
    ['raw URL field', JSON.stringify({ ...experiment(), url: 'https://evil.example' }), 'invalid_experiment'],
    ['shell field', JSON.stringify({ ...experiment(), shell: 'curl' }), 'invalid_experiment'],
    ['unknown operation', JSON.stringify({ ...experiment(), steps: [{ ...experiment().steps[0], operationId: 'github.rest.unknown.v1' }] }), 'invalid_experiment']
  ])('rejects %s with a typed error', async (_label, contents, code) => {
    const workspace = await mkdtemp(join(tmpdir(), 'aegishub-experiment-loader-'));
    const directory = join(workspace, '.aegishub', 'experiments');
    await mkdir(directory, { recursive: true });
    const path = join(directory, 'fixture.json');
    await writeFile(path, contents);
    const loader = new ExperimentLoader({ workspaceRoot: workspace, runtimeRoot: workspace });

    await expect(loader.load(path)).rejects.toMatchObject({ code });
  });

  it('rejects YAML aliases, duplicate keys, multiple documents, and paths outside the local experiment root', async () => {
    const workspace = await mkdtemp(join(tmpdir(), 'aegishub-experiment-loader-'));
    const directory = join(workspace, '.aegishub', 'experiments');
    await mkdir(directory, { recursive: true });
    const loader = new ExperimentLoader({ workspaceRoot: workspace, runtimeRoot: workspace });
    const cases: Array<[string, string]> = [
      ['alias', 'base: &base {schemaVersion: 1}\ncopy: *base'],
      ['duplicate', 'schemaVersion: 1\nschemaVersion: 1'],
      ['multiple', `${yamlExperiment()}---\n${yamlExperiment()}`]
    ];
    for (const [label, contents] of cases) {
      const path = join(directory, `${label}.yaml`);
      await writeFile(path, contents);
      await expect(loader.load(path)).rejects.toMatchObject({ code: 'invalid_experiment' });
    }
    const outside = join(workspace, 'outside.json');
    await writeFile(outside, JSON.stringify(experiment()));
    await expect(loader.load(outside)).rejects.toThrowError(new ExperimentLoaderError('experiment_path_denied'));
  });

  it('rejects symlinked experiment files and directories', async () => {
    const workspace = await mkdtemp(join(tmpdir(), 'aegishub-experiment-loader-'));
    const directory = join(workspace, '.aegishub', 'experiments');
    await mkdir(directory, { recursive: true });
    const real = join(directory, 'real.json');
    await writeFile(real, JSON.stringify(experiment()));
    const linked = join(directory, 'linked.json');
    await symlink(real, linked);
    const loader = new ExperimentLoader({ workspaceRoot: workspace, runtimeRoot: workspace });
    await expect(loader.load(linked)).rejects.toThrowError(new ExperimentLoaderError('experiment_symlink_rejected'));
  });
});
