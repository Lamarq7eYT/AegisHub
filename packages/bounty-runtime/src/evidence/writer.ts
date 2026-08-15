import { createHash, randomUUID } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { chmod, lstat, mkdir, open, readFile, rename, rm, stat } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { z } from 'zod';

import {
  analystInputSchema,
  buildAnalysisPack,
  candidateSchema,
  diffSchema,
  experimentSchema,
  observationSchema,
  policyStatusSchema,
  runManifestSchema,
  RunRedactor,
  type Candidate,
  type Diff,
  type Experiment,
  type ExperimentPlan,
  type JsonValue,
  type Observation,
  type PolicyStatus,
  type RunManifest
} from '@aegishub/bounty-core';

import { LabStore } from '../lab/store.js';
import type { CompletedRun, RunEvidenceSink } from '../experiments/runner.js';
import { renderReport, renderReproduction } from './report.js';

const RUNS_DIRECTORY = 'runs';
const CHECKSUM_FILE = 'checksums.txt';

const evidenceLabSnapshotSchema = z.object({
  labId: z.string().uuid(),
  ownerId: z.number().int().positive(),
  researcherId: z.number().int().positive(),
  repository: z.object({
    id: z.number().int().positive(),
    nodeId: z.string().min(1),
    owner: z.string().min(1),
    name: z.string().min(1),
    fullName: z.string().min(1)
  }).strict(),
  markerSha256: z.string().regex(/^[a-f0-9]{64}$/iu)
}).strict();
const evidenceManifestSchema = z.object({ run: runManifestSchema, lab: evidenceLabSnapshotSchema }).strict();
const evidencePolicySchema = z.object({ policy: policyStatusSchema, excerptIds: z.array(z.string().min(1)).min(1) }).strict();

export interface EvidenceLabSnapshot {
  readonly labId: string;
  readonly ownerId: number;
  readonly researcherId: number;
  readonly repository: {
    readonly id: number;
    readonly nodeId: string;
    readonly owner: string;
    readonly name: string;
    readonly fullName: string;
  };
  readonly markerSha256: string;
}

export interface EvidenceContext {
  readonly workspaceRoot: string;
  readonly lab: EvidenceLabSnapshot;
  readonly policy: PolicyStatus;
  readonly policyExcerptIds: readonly string[];
  readonly experiment: Experiment;
  readonly plan: ExperimentPlan & {
    readonly planFingerprint?: string;
    readonly manifestSha256?: string;
    readonly policyFingerprint?: string;
    readonly catalogFingerprint?: string;
  };
}

export interface EvidenceFile {
  readonly relativePath: string;
  readonly sha256: string;
  readonly bytes: number;
}

export interface EvidenceWriteResult {
  readonly runId: string;
  readonly path: string;
  readonly files: readonly EvidenceFile[];
}

export interface EvidenceExportResult {
  readonly runId: string;
  readonly path: string;
  readonly files: readonly EvidenceFile[];
}

export interface VerifiedEvidenceBundle {
  readonly path: string;
  readonly runId: string;
  readonly manifest: RunManifest;
  readonly policy: PolicyStatus;
  readonly experiment: Experiment;
  readonly plan: ExperimentPlan;
  readonly observations: readonly Observation[];
  readonly diff: Diff;
  readonly candidate?: Candidate;
}

export type EvidenceWriterErrorCode =
  | 'evidence_invalid_input'
  | 'evidence_target_exists'
  | 'evidence_bundle_missing'
  | 'evidence_export_exists'
  | 'evidence_symlink_rejected'
  | 'evidence_secret_rejected'
  | 'evidence_write_failed'
  | 'evidence_checksum_invalid'
  | 'evidence_filesystem_error';

export class EvidenceWriterError extends Error {
  constructor(readonly code: EvidenceWriterErrorCode, readonly temporaryPath?: string) {
    super(code);
    this.name = 'EvidenceWriterError';
  }
}

export class AtomicEvidenceWriter implements RunEvidenceSink {
  readonly #context: EvidenceContext;
  readonly #store: LabStore;

  constructor(context: EvidenceContext) {
    if (!isAbsolute(context.workspaceRoot)) throw new EvidenceWriterError('evidence_invalid_input');
    this.#context = context;
    this.#store = new LabStore(resolve(context.workspaceRoot));
  }

  async accept(run: CompletedRun): Promise<void> {
    await this.write(run);
  }

  async write(run: CompletedRun): Promise<EvidenceWriteResult> {
    const prepared = this.prepareBundle(run);
    const runsDirectory = await this.prepareRunsDirectory();
    const target = this.targetPath(run.manifest.runId);
    await rejectSymlink(target);
    if (await exists(target)) throw new EvidenceWriterError('evidence_target_exists');

    const temporary = join(runsDirectory, `.${run.manifest.runId}.${randomUUID()}.tmp`);
    await mkdir(temporary, { recursive: false, mode: 0o700 });
    try {
      const files = await this.writePrepared(temporary, prepared);
      await verifyFiles(temporary, files);
      await rename(temporary, target);
      await chmod(target, 0o700);
      return { runId: run.manifest.runId, path: target, files };
    } catch (error) {
      if (error instanceof EvidenceWriterError && error.code === 'evidence_secret_rejected') {
        await rm(temporary, { recursive: true, force: true }).catch(() => undefined);
        throw error;
      }
      if (error instanceof EvidenceWriterError) throw new EvidenceWriterError(error.code, temporary);
      throw new EvidenceWriterError('evidence_write_failed', temporary);
    } finally {
      prepared.redactor.destroy();
    }
  }

  async inspect(runId: string): Promise<VerifiedEvidenceBundle & { readonly verified: true }> {
    const target = this.targetPath(runId);
    await rejectSymlink(target);
    if (!(await exists(target))) throw new EvidenceWriterError('evidence_bundle_missing');
    try {
      const manifestEnvelope = parseJson<{ run: RunManifest }>(await readFile(join(target, 'manifest.json'), 'utf8'), evidenceManifestSchema.parse);
      const policyEnvelope = parseJson<{ policy: PolicyStatus }>(await readFile(join(target, 'policy.json'), 'utf8'), evidencePolicySchema.parse);
      const manifest = manifestEnvelope.run;
      const policy = policyEnvelope.policy;
      const experiment = parseJson<Experiment>(await readFile(join(target, 'experiment.json'), 'utf8'), experimentSchema.parse);
      const plan = parseJson<ExperimentPlan>(await readFile(join(target, 'plan.json'), 'utf8'), parsePlan);
      const observations = parseNdjson<Observation>(await readFile(join(target, 'observations.ndjson'), 'utf8'), observationSchema.parse);
      const diff = parseJson<Diff>(await readFile(join(target, 'diff.json'), 'utf8'), diffSchema.parse);
      const candidatePath = join(target, 'candidate.json');
      const candidate = await exists(candidatePath)
        ? parseJson<Candidate>(await readFile(candidatePath, 'utf8'), candidateSchema.parse)
        : undefined;
      const bundle: VerifiedEvidenceBundle = {
        path: target,
        runId,
        manifest,
        policy,
        experiment,
        plan,
        observations,
        diff,
        ...(candidate === undefined ? {} : { candidate })
      };
      await verifyChecksums(target);
      if (manifest.runId !== runId || diff.runId !== runId || (manifest.result === 'anomalous') !== (candidate !== undefined)) {
        throw new EvidenceWriterError('evidence_checksum_invalid');
      }
      return { ...bundle, verified: true };
    } catch (error) {
      if (error instanceof EvidenceWriterError) throw error;
      throw new EvidenceWriterError('evidence_checksum_invalid');
    }
  }

  async export(runId: string, outputDirectory: string): Promise<EvidenceExportResult> {
    const bundle = await this.inspect(runId);
    if (!isAbsolute(outputDirectory)) throw new EvidenceWriterError('evidence_invalid_input');
    const exportPath = resolve(outputDirectory);
    const root = resolve(this.#context.workspaceRoot);
    const rel = relative(root, exportPath);
    if (rel === '' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new EvidenceWriterError('evidence_invalid_input');
    await rejectSymlink(exportPath);
    if (await exists(exportPath)) throw new EvidenceWriterError('evidence_export_exists');
    const parent = resolve(exportPath, '..');
    await mkdir(parent, { recursive: true, mode: 0o700 });
    await rejectSymlink(parent);
    const temporary = join(parent, `.${exportPath.split(sep).at(-1) ?? 'export'}.${randomUUID()}.tmp`);
    await mkdir(temporary, { recursive: false, mode: 0o700 });
    const redactor = RunRedactor.create();
    try {
      const analyst = buildAnalysisPack(analystInputFromBundle(bundle));
      const serialized = JSON.stringify(redactor.redactJson(analyst as unknown as JsonValue));
      redactor.assertNoSuspectedSecret(serialized);
      const path = join(temporary, 'analysis-pack.json');
      await writeFileFlushed(path, `${serialized}\n`);
      const file = await fileInfo(temporary, 'analysis-pack.json');
      await rename(temporary, exportPath);
      return { runId, path: exportPath, files: [file] };
    } catch (error) {
      await rm(temporary, { recursive: true, force: true }).catch(() => undefined);
      if (error instanceof EvidenceWriterError) throw error;
      throw new EvidenceWriterError('evidence_write_failed');
    } finally {
      redactor.destroy();
    }
  }

  private prepareBundle(run: CompletedRun): PreparedBundle {
    try {
      const manifest = runManifestSchema.parse(run.manifest);
      const policy = policyStatusSchema.parse(this.#context.policy);
      const experiment = experimentSchema.parse(this.#context.experiment);
      const plan = parsePlan(this.#context.plan);
      const observations = run.observations.map((observation) => observationSchema.parse(observation));
      const diff = diffSchema.parse(run.diff);
      const candidate = run.candidate === undefined ? undefined : candidateSchema.parse(run.candidate);
      if (manifest.runId !== run.manifest.runId || manifest.experimentId !== experiment.id || diff.runId !== manifest.runId) {
        throw new EvidenceWriterError('evidence_invalid_input');
      }
      if ((manifest.result === 'anomalous') !== (candidate !== undefined)) throw new EvidenceWriterError('evidence_invalid_input');

      const redactor = RunRedactor.create();
      const values: Record<string, string> = {
        'manifest.json': JSON.stringify(redactor.redactJson({ run: manifest, lab: this.#context.lab } as unknown as JsonValue)),
        'policy.json': JSON.stringify(redactor.redactJson({ policy: sanitizePolicy(policy), excerptIds: this.#context.policyExcerptIds } as unknown as JsonValue)),
        'experiment.json': JSON.stringify(redactor.redactJson(experiment as unknown as JsonValue)),
        'plan.json': JSON.stringify(redactor.redactJson(plan as unknown as JsonValue)),
        'observations.ndjson': observations.map((observation) => JSON.stringify(redactor.redactJson(observation as unknown as JsonValue))).join('\n') + '\n',
        'diff.json': JSON.stringify(redactor.redactJson(diff as unknown as JsonValue)),
        'report.md': '',
        'reproduce.md': ''
      };
      const bundle: VerifiedEvidenceBundle = {
        path: '',
        runId: manifest.runId,
        manifest,
        policy,
        experiment,
        plan,
        observations,
        diff,
        ...(candidate === undefined ? {} : { candidate })
      };
      values['report.md'] = renderReport(bundle);
      values['reproduce.md'] = renderReproduction(bundle);
      for (const content of Object.values(values)) redactor.assertNoSuspectedSecret(content);
      const files = Object.entries(values).map(([relativePath, content]) => ({ relativePath, content }));
      if (candidate !== undefined) files.push({ relativePath: 'candidate.json', content: JSON.stringify(redactor.redactJson(candidate as unknown as JsonValue)) });
      const checksums = files
        .sort((left, right) => left.relativePath.localeCompare(right.relativePath))
        .map(({ relativePath, content }) => `${sha256Text(content)}  ${relativePath}`)
        .join('\n') + '\n';
      redactor.assertNoSuspectedSecret(checksums);
      files.push({ relativePath: CHECKSUM_FILE, content: checksums });
      return {
        manifest,
        policy,
        experiment,
        plan,
        observations,
        diff,
        ...(candidate === undefined ? {} : { candidate }),
        files,
        redactor
      };
    } catch (error) {
      if (error instanceof EvidenceWriterError) throw error;
      if (error instanceof Error && error.message.startsWith('suspected_secret:')) throw new EvidenceWriterError('evidence_secret_rejected');
      throw new EvidenceWriterError('evidence_invalid_input');
    }
  }

  private async writePrepared(directory: string, prepared: PreparedBundle): Promise<readonly EvidenceFile[]> {
    const output: EvidenceFile[] = [];
    for (const file of prepared.files) {
      const path = safeChild(directory, file.relativePath);
      await writeFileFlushed(path, file.content);
      output.push({ relativePath: file.relativePath, sha256: sha256Text(file.content), bytes: Buffer.byteLength(file.content, 'utf8') });
    }
    return output.sort((left, right) => left.relativePath.localeCompare(right.relativePath));
  }

  private async prepareRunsDirectory(): Promise<string> {
    const stateDirectory = join(this.#store.workspaceRoot(), '.aegishub');
    await rejectSymlink(stateDirectory);
    try {
      await mkdir(stateDirectory, { recursive: false, mode: 0o700 });
    } catch (error) {
      if (!isAlreadyExists(error)) throw new EvidenceWriterError('evidence_filesystem_error');
    }
    await rejectSymlink(stateDirectory);
    await chmod(stateDirectory, 0o700);
    const directory = this.#store.statePath(RUNS_DIRECTORY);
    await rejectSymlink(directory);
    try {
      await mkdir(directory, { recursive: false, mode: 0o700 });
    } catch (error) {
      if (!isAlreadyExists(error)) throw new EvidenceWriterError('evidence_filesystem_error');
    }
    await rejectSymlink(directory);
    await chmod(directory, 0o700);
    return directory;
  }

  private targetPath(runId: string): string {
    if (!/^[0-9a-f-]{36}$/iu.test(runId)) throw new EvidenceWriterError('evidence_invalid_input');
    return this.#store.statePath(RUNS_DIRECTORY, runId);
  }
}

interface PreparedBundle {
  readonly manifest: RunManifest;
  readonly policy: PolicyStatus;
  readonly experiment: Experiment;
  readonly plan: ExperimentPlan;
  readonly observations: readonly Observation[];
  readonly diff: Diff;
  readonly candidate?: Candidate;
  readonly files: Array<{ relativePath: string; content: string }>;
  readonly redactor: RunRedactor;
}

function sanitizePolicy(policy: PolicyStatus): JsonValue {
  return {
    schemaVersion: 1,
    policyVersion: policy.policyVersion,
    state: policy.state,
    checkedAt: policy.checkedAt,
    sourceStatuses: policy.sourceStatuses.map((status) => ({ sourceId: status.sourceId, state: status.state, checkedAt: status.checkedAt, ...(status.observedSha256 === undefined ? {} : { observedSha256: status.observedSha256 }) }))
  } as unknown as JsonValue;
}

function analystInputFromBundle(bundle: VerifiedEvidenceBundle) {
  return analystInputSchema.parse({
    schemaVersion: 1,
    labId: bundle.manifest.labId,
    runId: bundle.runId,
    evidenceIds: bundle.observations.map((observation) => observation.observationId),
    sanitizedObservations: bundle.observations.map((observation) => ({ schemaVersion: 1, observationId: observation.observationId, actor: observation.actor, status: observation.status, normalizedBody: observation.normalizedBody, bodySha256: observation.bodySha256 })),
    priorSummaries: [bundle.diff.summary],
    policyExcerptIds: ['policy-v1'],
    availableOperationIds: bundle.plan.operations.map((operation) => operation.operationId as never)
  });
}

function parsePlan(value: unknown): ExperimentPlan {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid_plan');
  const candidate = value as Record<string, unknown>;
  if (candidate.schemaVersion !== 1 || typeof candidate.planId !== 'string' || typeof candidate.experimentId !== 'string' || typeof candidate.experimentVersion !== 'number' || candidate.budgets === undefined || !Array.isArray(candidate.operations)) throw new Error('invalid_plan');
  return value as ExperimentPlan;
}

function parseJson<T>(serialized: string, parser: (value: unknown) => T): T {
  return parser(JSON.parse(serialized));
}

function parseNdjson<T>(serialized: string, parser: (value: unknown) => T): T[] {
  if (!serialized.endsWith('\n')) throw new Error('invalid_ndjson');
  return serialized.trimEnd().split('\n').map((line) => parser(JSON.parse(line)));
}

async function verifyFiles(directory: string, files: readonly EvidenceFile[]): Promise<void> {
  for (const file of files) {
    const content = await readFile(safeChild(directory, file.relativePath), 'utf8');
    if (sha256Text(content) !== file.sha256 || Buffer.byteLength(content, 'utf8') !== file.bytes) throw new EvidenceWriterError('evidence_checksum_invalid');
  }
  await verifyChecksums(directory);
}

async function verifyChecksums(directory: string): Promise<void> {
  const checksumPath = safeChild(directory, CHECKSUM_FILE);
  const serialized = await readFile(checksumPath, 'utf8');
  const entries = serialized.trimEnd().split('\n').map((line) => {
    const separator = line.indexOf('  ');
    if (separator < 0) throw new EvidenceWriterError('evidence_checksum_invalid');
    return { digest: line.slice(0, separator), relativePath: line.slice(separator + 2) };
  });
  if (entries.length === 0 || entries.some((entry) => !/^[a-f0-9]{64}$/iu.test(entry.digest) || entry.relativePath === CHECKSUM_FILE || entry.relativePath.includes('/') && entry.relativePath.split('/').some((part) => part === '..'))) throw new EvidenceWriterError('evidence_checksum_invalid');
  const sorted = [...entries].sort((left, right) => left.relativePath.localeCompare(right.relativePath));
  if (JSON.stringify(entries) !== JSON.stringify(sorted)) throw new EvidenceWriterError('evidence_checksum_invalid');
  for (const entry of entries) {
    const content = await readFile(safeChild(directory, entry.relativePath), 'utf8');
    if (sha256Text(content) !== entry.digest) throw new EvidenceWriterError('evidence_checksum_invalid');
  }
}

async function writeFileFlushed(path: string, content: string): Promise<void> {
  const handle = await open(path, 'wx', 0o600);
  try {
    await handle.write(content, null, 'utf8');
    await handle.sync();
    await handle.chmod(0o600);
  } finally {
    await handle.close();
  }
}

async function fileInfo(directory: string, relativePath: string): Promise<EvidenceFile> {
  const content = await readFile(safeChild(directory, relativePath), 'utf8');
  const info = await stat(safeChild(directory, relativePath));
  return { relativePath, sha256: sha256Text(content), bytes: info.size };
}

function safeChild(directory: string, relativePath: string): string {
  const candidate = resolve(directory, relativePath);
  const rel = relative(directory, candidate);
  if (rel === '' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new EvidenceWriterError('evidence_invalid_input');
  return candidate;
}

async function rejectSymlink(path: string): Promise<void> {
  try {
    const info = await lstat(path);
    if (info.isSymbolicLink()) throw new EvidenceWriterError('evidence_symlink_rejected');
  } catch (error) {
    if (error instanceof EvidenceWriterError) throw error;
    if (!isMissing(error)) throw new EvidenceWriterError('evidence_filesystem_error');
  }
}

function sha256Text(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (isMissing(error)) return false;
    throw new EvidenceWriterError('evidence_filesystem_error');
  }
}

function isMissing(error: unknown): boolean {
  return isNodeError(error, 'ENOENT');
}

function isAlreadyExists(error: unknown): boolean {
  return isNodeError(error, 'EEXIST');
}

function isNodeError(error: unknown, code: string): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && (error as { code?: unknown }).code === code;
}
