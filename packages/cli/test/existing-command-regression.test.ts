import { mkdtemp, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { execa } from 'execa';
import { describe, expect, it } from 'vitest';

const cliRoot = new URL('..', import.meta.url).pathname;

async function runCli(...args: string[]) {
  return execa('pnpm', ['exec', 'tsx', 'src/index.ts', ...args], { cwd: cliRoot, reject: false });
}

describe('legacy CLI regression surface', () => {
  it('keeps scan, report, auth and bounty in help', async () => {
    const result = await runCli('--help');
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toMatch(/scan/);
    expect(result.stdout).toMatch(/report/);
    expect(result.stdout).toMatch(/auth/);
    expect(result.stdout).toMatch(/bounty/);
  });

  it('keeps the existing top-level auth guidance', async () => {
    const result = await runCli('auth');
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('Set GITHUB_TOKEN to scan private repositories or increase GitHub API limits.');
    expect(result.stdout).toContain('export GITHUB_TOKEN="your_token_here"');
  });

  it('continues parsing and printing an existing synthetic report', async () => {
    const workspace = await mkdtemp('/tmp/aegishub-cli-report-');
    const reportPath = join(workspace, 'report.json');
    await writeFile(reportPath, JSON.stringify({ repo: 'synthetic/repository', commit: 'fixture', scanned_at: '2026-08-13T12:00:00.000Z', score: 100, findings: [], stats: { files_scanned: 1, lines_scanned: 2, duration_ms: 1 } }));
    const result = await runCli('report', reportPath);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('AegisHub Security Report');
    expect(result.stdout).toContain('Score: 100/100');
  });

  it('does not make network work for bounty help and never leaks a seeded token on failed login', async () => {
    const help = await runCli('bounty', '--help');
    expect(help.exitCode).toBe(0);
    expect(help.stdout).toContain('experiment');
    expect(help.stdout).not.toContain('ghp_SYNTHETIC_TOKEN');

    const failedLogin = await execa('pnpm', ['exec', 'tsx', 'src/index.ts', 'bounty', 'auth', 'login', '--actor', 'owner'], {
      cwd: cliRoot,
      reject: false,
      env: { ...process.env, AEGISHUB_GITHUB_APP_CLIENT_ID: 'synthetic-client-id', GITHUB_TOKEN: 'ghp_SYNTHETIC_TOKEN' }
    });
    expect(`${failedLogin.stdout}\n${failedLogin.stderr}`).not.toContain('ghp_SYNTHETIC_TOKEN');
  });
});
