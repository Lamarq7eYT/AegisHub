import { lstat, readFile } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';

import { parseAllDocuments } from 'yaml';
import {
  experimentSchema,
  isExperimentOperation,
  sha256StableJson,
  stableJson,
  validateOperationParameters,
  type Experiment,
  type JsonValue
} from '@aegishub/bounty-core';

const MAX_EXPERIMENT_BYTES = 65_536;

export type ExperimentLoaderErrorCode =
  | 'experiment_too_large'
  | 'invalid_experiment'
  | 'experiment_path_denied'
  | 'experiment_symlink_rejected'
  | 'experiment_filesystem_error';

export class ExperimentLoaderError extends Error {
  constructor(readonly code: ExperimentLoaderErrorCode) {
    super(code);
    this.name = 'ExperimentLoaderError';
  }
}

export interface ExperimentLoaderOptions {
  readonly workspaceRoot: string;
  readonly runtimeRoot: string;
}

export interface LoadedExperiment {
  readonly experiment: Experiment;
  readonly sha256: string;
  readonly path: string;
}

export class ExperimentLoader {
  readonly #workspaceRoot: string;
  readonly #runtimeRoot: string;

  constructor(options: ExperimentLoaderOptions) {
    this.#workspaceRoot = resolve(options.workspaceRoot);
    this.#runtimeRoot = resolve(options.runtimeRoot);
  }

  async load(path: string): Promise<LoadedExperiment> {
    const absolutePath = this.resolveAllowedPath(path);
    await this.rejectSymlinkPath(absolutePath);
    let bytes: Uint8Array;
    try {
      bytes = await readFile(absolutePath);
    } catch {
      throw new ExperimentLoaderError('experiment_filesystem_error');
    }
    if (bytes.byteLength > MAX_EXPERIMENT_BYTES) throw new ExperimentLoaderError('experiment_too_large');
    const text = new globalThis.TextDecoder().decode(bytes);
    const value = this.parse(text, absolutePath.endsWith('.json'));
    const parsed = experimentSchema.safeParse(value);
    if (!parsed.success) throw new ExperimentLoaderError('invalid_experiment');
    for (const step of parsed.data.steps) {
      try {
        const descriptorIsVisible = isExperimentOperation(step.operationId as never);
        if (!descriptorIsVisible) throw new Error('operation_not_experiment_visible');
        validateOperationParameters(step.operationId as never, step.parameters);
      } catch {
        throw new ExperimentLoaderError('invalid_experiment');
      }
    }
    const json = JSON.parse(stableJson(parsed.data)) as JsonValue;
    return { experiment: parsed.data, sha256: sha256StableJson(json), path: absolutePath };
  }

  private resolveAllowedPath(path: string): string {
    if (typeof path !== 'string' || path.length === 0) throw new ExperimentLoaderError('experiment_path_denied');
    const absolute = resolve(path);
    const roots = [join(this.#workspaceRoot, '.aegishub', 'experiments'), join(this.#runtimeRoot, 'experiments')];
    const allowed = roots.some((root) => {
      const rel = relative(root, absolute);
      return rel !== '' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel) && !rel.includes('\u0000');
    });
    if (!allowed) throw new ExperimentLoaderError('experiment_path_denied');
    return absolute;
  }

  private parse(text: string, isJson: boolean): unknown {
    try {
      const documents = parseAllDocuments(text, {
        schema: 'core',
        version: '1.2',
        uniqueKeys: true,
        stringKeys: true
      });
      if (documents.length !== 1) throw new Error('multiple_documents');
      const document = documents[0];
      if (document === undefined || document.errors.length > 0) throw new Error('yaml_parse_error');
      const value = document.toJS({ maxAliasCount: 0 });
      if (isJson && typeof value !== 'object') throw new Error('json_root_invalid');
      return value;
    } catch {
      throw new ExperimentLoaderError('invalid_experiment');
    }
  }

  private async rejectSymlinkPath(path: string): Promise<void> {
    const localRoot = join(this.#workspaceRoot, '.aegishub', 'experiments');
    const runtimeRoot = join(this.#runtimeRoot, 'experiments');
    const root = path.startsWith(`${localRoot}${sep}`) ? localRoot : runtimeRoot;
    let current = root;
    try {
      const rootInfo = await lstat(current);
      if (rootInfo.isSymbolicLink()) throw new ExperimentLoaderError('experiment_symlink_rejected');
      for (const segment of relative(root, path).split(sep)) {
        current = join(current, segment);
        const info = await lstat(current);
        if (info.isSymbolicLink()) throw new ExperimentLoaderError('experiment_symlink_rejected');
      }
    } catch (error) {
      if (error instanceof ExperimentLoaderError) throw error;
      throw new ExperimentLoaderError('experiment_filesystem_error');
    }
  }
}
