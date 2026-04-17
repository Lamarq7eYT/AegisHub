#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { access, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { dirname, extname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import chalk from 'chalk';
import { Command } from 'commander';
import ora from 'ora';

type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

type SourceFileInput = {
  path: string;
  language?: string;
  content: string;
};

type EngineInput = {
  repo: string;
  commit: string;
  files: SourceFileInput[];
};

type Finding = {
  file_path: string;
  line: number;
  column: number;
  rule_id: string;
  severity: Severity;
  message: string;
  snippet: string;
  cwe_id: string;
};

type ScanReport = {
  repo: string;
  commit: string;
  scanned_at: string;
  score: number;
  findings: Finding[];
  stats: {
    files_scanned: number;
    lines_scanned: number;
    duration_ms: number;
  };
};

type GitHubTreeResponse = {
  tree?: GitHubTreeEntry[];
  truncated?: boolean;
};

type GitHubTreeEntry = {
  path?: string;
  type?: string;
  size?: number;
  url?: string;
};

type GitHubBlobResponse = {
  content?: string;
  encoding?: string;
};

const maxFileBytes = 500 * 1024;
const skipSegments = new Set([
  '.git',
  '.turbo',
  'build',
  'coverage',
  'dist',
  'node_modules',
  'pkg',
  'target',
  'vendor',
]);

const languageByExtension = new Map<string, string>([
  ['.cjs', 'javascript'],
  ['.css', 'css'],
  ['.go', 'go'],
  ['.html', 'html'],
  ['.java', 'java'],
  ['.js', 'javascript'],
  ['.jsx', 'javascript'],
  ['.mjs', 'javascript'],
  ['.php', 'php'],
  ['.py', 'python'],
  ['.rb', 'ruby'],
  ['.rs', 'rust'],
  ['.ts', 'typescript'],
  ['.tsx', 'typescript'],
]);

const textExtensions = new Set([
  '.cjs',
  '.conf',
  '.css',
  '.env',
  '.go',
  '.html',
  '.java',
  '.js',
  '.json',
  '.jsx',
  '.md',
  '.mjs',
  '.php',
  '.py',
  '.rb',
  '.rs',
  '.toml',
  '.ts',
  '.tsx',
  '.txt',
  '.xml',
  '.yaml',
  '.yml',
]);

const program = new Command();

program
  .name('aegishub')
  .description('Scan local directories or GitHub repositories with the AegisHub engine.')
  .version('0.1.0');

program
  .command('scan')
  .description('Scan a local directory, GitHub URL, or owner/repo target.')
  .argument('[target]', 'Directory, GitHub URL, or owner/repo', '.')
  .option('--ref <ref>', 'Git ref for GitHub repository scans')
  .option('--json', 'Print the full JSON report')
  .option('--output <path>', 'Write the full JSON report to a file', 'aegishub-report.json')
  .action(async (target: string, options: { ref?: string; json?: boolean; output: string }) => {
    await runScan(target, options);
  });

program
  .command('report')
  .description('Read and print a saved AegisHub JSON report.')
  .argument('[path]', 'Report path', 'aegishub-report.json')
  .action(async (reportPath: string) => {
    // The report command intentionally reads a user-selected report file.
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    const raw = await readFile(reportPath, 'utf8');
    const report = parseReport(raw);
    printReport(report);
  });

program
  .command('auth')
  .description('Show how to authenticate GitHub API requests.')
  .action(() => {
    console.log('Set GITHUB_TOKEN to scan private repositories or increase GitHub API limits.');
    console.log('');
    console.log('PowerShell:');
    console.log('$env:GITHUB_TOKEN="your_token_here"');
    console.log('');
    console.log('bash/zsh:');
    console.log('export GITHUB_TOKEN="your_token_here"');
  });

program.parseAsync().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'Unknown CLI error';
  console.error(chalk.red(`AegisHub failed: ${message}`));
  process.exitCode = 1;
});

async function runScan(
  target: string,
  options: { ref?: string; json?: boolean; output: string },
): Promise<void> {
  const spinner = ora(`Preparing scan for ${target}`).start();

  try {
    const input = await buildEngineInput(target, options.ref);
    spinner.text = `Analyzing ${input.files.length} files with the Rust engine`;

    const report = await runEngine(input);
    spinner.succeed(`Scan completed for ${report.repo}`);

    const outputPath = resolveUserPath(options.output);
    // The output path is explicitly provided by the CLI user.
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');

    if (options.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      printReport(report);
      console.log('');
      console.log(chalk.dim(`Full JSON report written to ${outputPath}`));
    }
  } catch (error) {
    spinner.fail('Scan failed');
    throw error;
  }
}

async function buildEngineInput(target: string, ref?: string): Promise<EngineInput> {
  const githubTarget = parseGitHubTarget(target);

  if (githubTarget) {
    return fetchGitHubRepository(githubTarget.owner, githubTarget.repo, ref);
  }

  return scanLocalDirectory(target);
}

async function scanLocalDirectory(target: string): Promise<EngineInput> {
  const root = resolveUserPath(target);
  await access(root, constants.R_OK);

  const files = await collectLocalFiles(root);
  const commit = createHash('sha256')
    .update(files.map((file) => `${file.path}:${file.content.length}`).join('\n'))
    .digest('hex')
    .slice(0, 12);

  return {
    repo: root.split(sep).filter(Boolean).at(-1) ?? 'local-repository',
    commit,
    files,
  };
}

async function collectLocalFiles(root: string): Promise<SourceFileInput[]> {
  const collected: SourceFileInput[] = [];
  const pending = [root];

  while (pending.length > 0) {
    const current = pending.pop();
    if (!current) {
      continue;
    }

    // Directory scanning is the CLI's core behavior; paths are filtered before analysis.
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    const entries = await readdir(current, { withFileTypes: true });

    for (const entry of entries) {
      const absolutePath = join(current, entry.name);
      const relativePath = toPosixPath(relative(root, absolutePath));

      if (shouldSkipPath(relativePath)) {
        continue;
      }

      if (entry.isDirectory()) {
        pending.push(absolutePath);
        continue;
      }

      if (!entry.isFile() || !isSupportedTextPath(relativePath)) {
        continue;
      }

      // Files are constrained by skip rules and maximum size before being read.
      // eslint-disable-next-line security/detect-non-literal-fs-filename
      const info = await stat(absolutePath);
      if (info.size > maxFileBytes) {
        continue;
      }

      // Files are constrained by skip rules and maximum size before being read.
      // eslint-disable-next-line security/detect-non-literal-fs-filename
      const buffer = await readFile(absolutePath);
      if (isLikelyBinary(buffer)) {
        continue;
      }

      collected.push({
        ...createSourceFileInput(relativePath, buffer.toString('utf8')),
      });
    }
  }

  return collected.sort((left, right) => left.path.localeCompare(right.path));
}

async function fetchGitHubRepository(owner: string, repo: string, ref?: string): Promise<EngineInput> {
  const token = process.env.GITHUB_TOKEN;
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'aegishub-cli',
    'X-GitHub-Api-Version': '2022-11-28',
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const repoResponse = await githubFetch<{ default_branch?: string; full_name?: string }>(
    `https://api.github.com/repos/${owner}/${repo}`,
    headers,
  );
  const gitRef = ref ?? repoResponse.default_branch ?? 'main';
  const treeResponse = await githubFetch<GitHubTreeResponse>(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(gitRef)}?recursive=1`,
    headers,
  );

  if (treeResponse.truncated) {
    console.warn(chalk.yellow('GitHub returned a truncated tree. The scan uses available files only.'));
  }

  const entries = (treeResponse.tree ?? [])
    .filter((entry) => entry.type === 'blob')
    .filter((entry) => typeof entry.path === 'string' && typeof entry.url === 'string')
    .filter((entry) => !shouldSkipPath(entry.path ?? ''))
    .filter((entry) => isSupportedTextPath(entry.path ?? ''))
    .filter((entry) => (entry.size ?? 0) <= maxFileBytes)
    .slice(0, 10_000);

  const files: SourceFileInput[] = [];

  for (const entry of entries) {
    if (!entry.path || !entry.url) {
      continue;
    }

    const blob = await githubFetch<GitHubBlobResponse>(entry.url, headers);
    if (blob.encoding !== 'base64' || !blob.content) {
      continue;
    }

    const buffer = Buffer.from(blob.content.replace(/\n/g, ''), 'base64');
    if (isLikelyBinary(buffer)) {
      continue;
    }

    files.push({
      ...createSourceFileInput(entry.path, buffer.toString('utf8')),
    });
  }

  return {
    repo: repoResponse.full_name ?? `${owner}/${repo}`,
    commit: gitRef,
    files,
  };
}

async function githubFetch<T>(url: string, headers: Record<string, string>): Promise<T> {
  const response = await fetch(url, { headers });

  if (!response.ok) {
    const remaining = response.headers.get('x-ratelimit-remaining');
    const reset = response.headers.get('x-ratelimit-reset');
    const rateLimitHint =
      remaining === '0' && reset
        ? ` GitHub API rate limit is exhausted until ${new Date(Number(reset) * 1000).toISOString()}.`
        : '';
    throw new Error(`GitHub request failed with ${response.status}.${rateLimitHint}`);
  }

  return (await response.json()) as T;
}

async function runEngine(input: EngineInput): Promise<ScanReport> {
  const coreManifest = resolve(dirname(fileURLToPath(import.meta.url)), '../../core/Cargo.toml');
  const child = spawn(
    'cargo',
    ['run', '--quiet', '--manifest-path', coreManifest, '--bin', 'aegishub-engine'],
    {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    },
  );

  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];

  child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
  child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
  child.stdin.write(JSON.stringify(input));
  child.stdin.end();

  const exitCode = await new Promise<number | null>((resolveExit) => {
    child.on('close', resolveExit);
  });

  if (exitCode !== 0) {
    throw new Error(Buffer.concat(stderr).toString('utf8') || `Engine exited with ${exitCode}`);
  }

  return parseReport(Buffer.concat(stdout).toString('utf8'));
}

function parseReport(raw: string): ScanReport {
  return JSON.parse(raw) as ScanReport;
}

function printReport(report: ScanReport): void {
  const grouped = groupBySeverity(report.findings);

  console.log('');
  console.log(chalk.bold('AegisHub Security Report'));
  console.log(chalk.dim('━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log(
    `Score: ${colorScore(report.score)(`${report.score}/100`)}   Files: ${report.stats.files_scanned}   Findings: ${report.findings.length}`,
  );
  console.log('');

  for (const severity of ['Critical', 'High', 'Medium', 'Low', 'Info'] as const) {
    const items = grouped.get(severity) ?? [];
    if (items.length === 0) {
      continue;
    }

    console.log(colorSeverity(severity)(`${severity.toUpperCase()} (${items.length})`));

    for (const finding of items.slice(0, 10)) {
      console.log(
        `  ${chalk.bold('▸')} ${finding.file_path}:${finding.line} - ${finding.message} (${finding.cwe_id})`,
      );
    }

    if (items.length > 10) {
      console.log(chalk.dim(`  ...and ${items.length - 10} more ${severity} findings`));
    }

    console.log('');
  }
}

function groupBySeverity(findings: Finding[]): Map<Severity, Finding[]> {
  const grouped = new Map<Severity, Finding[]>();

  for (const finding of findings) {
    const current = grouped.get(finding.severity) ?? [];
    current.push(finding);
    grouped.set(finding.severity, current);
  }

  return grouped;
}

function parseGitHubTarget(target: string): { owner: string; repo: string } | undefined {
  const trimmed = target.trim();
  const urlMatch = trimmed.match(/^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/?$/);
  const shorthandMatch = trimmed.match(/^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/);
  const match = urlMatch ?? shorthandMatch;

  if (!match?.[1] || !match[2]) {
    return undefined;
  }

  return {
    owner: match[1],
    repo: match[2].replace(/\.git$/, ''),
  };
}

function shouldSkipPath(filePath: string): boolean {
  const normalized = toPosixPath(filePath);
  const segments = normalized.split('/');

  if (segments.some((segment) => skipSegments.has(segment))) {
    return true;
  }

  return (
    normalized.endsWith('.min.js') ||
    normalized.endsWith('.lock') ||
    normalized.endsWith('lock.yaml') ||
    normalized.endsWith('lock.yml')
  );
}

function isSupportedTextPath(filePath: string): boolean {
  return textExtensions.has(extname(filePath).toLowerCase());
}

function inferLanguage(filePath: string): string | undefined {
  return languageByExtension.get(extname(filePath).toLowerCase());
}

function createSourceFileInput(filePath: string, content: string): SourceFileInput {
  const language = inferLanguage(filePath);

  if (!language) {
    return {
      path: filePath,
      content,
    };
  }

  return {
    path: filePath,
    language,
    content,
  };
}

function isLikelyBinary(buffer: Buffer): boolean {
  return buffer.includes(0);
}

function toPosixPath(filePath: string): string {
  return filePath.split(sep).join('/');
}

function resolveUserPath(target: string): string {
  return resolve(process.env.INIT_CWD ?? process.cwd(), target);
}

function colorSeverity(severity: Severity): (value: string) => string {
  switch (severity) {
    case 'Critical':
      return chalk.red.bold;
    case 'High':
      return chalk.yellow.bold;
    case 'Medium':
      return chalk.cyan.bold;
    case 'Low':
      return chalk.gray.bold;
    case 'Info':
      return chalk.white.bold;
  }
}

function colorScore(score: number): (value: string) => string {
  if (score >= 85) {
    return chalk.green.bold;
  }

  if (score >= 65) {
    return chalk.yellow.bold;
  }

  if (score >= 45) {
    return chalk.hex('#f97316').bold;
  }

  return chalk.red.bold;
}
