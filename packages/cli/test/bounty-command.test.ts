import { describe, expect, it, vi } from 'vitest';
import { Command } from 'commander';

import {
  BountyCliError,
  registerBountyCommands,
  type BountyCliServices
} from '../src/bounty/register-bounty-command.js';

function services(overrides: Partial<BountyCliServices> = {}): BountyCliServices {
  return {
    policy: { status: vi.fn(async () => ({ state: 'current', policyVersion: 'policy-v1', warnings: [] })) },
    auth: {
      login: vi.fn(async () => ({ actor: 'owner', login: 'owner-fixture', id: 1001, persisted: false })),
      status: vi.fn(async () => ({ records: [], sessionActors: [] })),
      logout: vi.fn(async () => undefined),
      revokeLocal: vi.fn(async () => ({ revokedActors: ['owner'] }))
    },
    lab: {
      init: vi.fn(async () => ({ labId: '95f38cca-42e2-4b7d-82e6-f13f4549b2f3', repositoryId: 3003 })),
      verify: vi.fn(async () => ({ status: 'verified', labId: '95f38cca-42e2-4b7d-82e6-f13f4549b2f3' })),
      status: vi.fn(async () => ({ status: 'verified', labId: '95f38cca-42e2-4b7d-82e6-f13f4549b2f3' }))
    },
    experiment: {
      list: vi.fn(async () => [{ id: 'repo.private.contents-read-boundary.v1', version: 1 }]),
      plan: vi.fn(async () => ({ planId: '3e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12', fingerprint: 'a'.repeat(64), operations: [], budgets: { maxMutations: 0 } })),
      run: vi.fn(async () => ({ runId: '3e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12', state: 'expected', candidate: undefined }))
    },
    run: { inspect: vi.fn(async () => ({ runId: '3e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12', verified: true })) },
    evidence: { export: vi.fn(async () => ({ runId: '3e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12', path: '/tmp/sanitized-pack' })) },
    stop: { request: vi.fn(async () => ({ requested: true })) },
    terminal: {
      isInteractive: () => true,
      approve: vi.fn(async () => true),
      print: vi.fn(),
      warn: vi.fn(),
      close: vi.fn()
    },
    ...overrides
  };
}

function makeCommand(fake = services()): { command: Command; fake: BountyCliServices } {
  const command = new Command();
  command.exitOverride();
  command.name('aegishub');
  registerBountyCommands(command, fake);
  return { command, fake };
}

describe('bounty command tree', () => {
  it('registers the exact guarded command tree without performing network work', () => {
    const { command } = makeCommand();
    const help = command.commands.find((child) => child.name() === 'bounty')?.helpInformation() ?? '';
    expect(help).toContain('policy');
    expect(help).toContain('auth');
    expect(help).toContain('lab');
    expect(help).toContain('experiment');
    expect(help).toContain('run');
    expect(help).toContain('evidence');
    expect(help).toContain('stop');
  });

  it('exposes all required nested commands and options', () => {
    const { command } = makeCommand();
    const bounty = command.commands.find((child) => child.name() === 'bounty');
    expect(bounty?.commands.map((child) => child.name())).toEqual(expect.arrayContaining(['policy', 'auth', 'lab', 'experiment', 'run', 'evidence', 'stop']));
    const auth = bounty?.commands.find((child) => child.name() === 'auth');
    expect(auth?.commands.map((child) => child.name())).toEqual(expect.arrayContaining(['login', 'status', 'logout', 'revoke-local']));
    const experiment = bounty?.commands.find((child) => child.name() === 'experiment');
    expect(experiment?.commands.map((child) => child.name())).toEqual(expect.arrayContaining(['list', 'plan', 'run']));
    const evidenceExport = bounty?.commands.find((child) => child.name() === 'evidence')?.commands.find((child) => child.name() === 'export');
    expect(evidenceExport?.options.some((option) => option.long === '--output')).toBe(true);
  });

  it('uses injected services for plan and never executes a transport operation', async () => {
    const fake = services();
    const { command } = makeCommand(fake);
    await command.parseAsync(['node', 'aegishub', 'bounty', 'experiment', 'plan', 'repo.private.contents-read-boundary.v1']);
    expect(fake.experiment.plan).toHaveBeenCalledWith('repo.private.contents-read-boundary.v1');
    expect(fake.experiment.run).not.toHaveBeenCalled();
  });

  it('requires the actor enum and sanitizes typed service failures', async () => {
    const fake = services({ auth: { ...services().auth, login: vi.fn(async () => { throw new BountyCliError('auth_failed', 'synthetic login failed'); }) } });
    const { command } = makeCommand(fake);
    await expect(command.parseAsync(['node', 'aegishub', 'bounty', 'auth', 'login', '--actor', 'administrator'])).rejects.toBeDefined();
    await expect(command.parseAsync(['node', 'aegishub', 'bounty', 'auth', 'login', '--actor', 'owner'])).rejects.toMatchObject({ code: 'auth_failed', message: 'synthetic login failed' });
    expect(JSON.stringify(fake)).not.toContain('ghp_');
  });

  it('reports expected and anomalous outcomes without claiming severity or submission', async () => {
    const expectedFake = services();
    const expected = makeCommand(expectedFake).command;
    await expected.parseAsync(['node', 'aegishub', 'bounty', 'experiment', 'run', 'repo.private.contents-read-boundary.v1']);
    expect(expectedFake.terminal.print).toHaveBeenCalledWith(expect.stringContaining('expected'));
    expect(expectedFake.terminal.print).not.toHaveBeenCalledWith(expect.stringMatching(/severity|submit|confirmed/i));

    const anomalousFake = services({ experiment: { ...services().experiment, run: vi.fn(async () => ({ runId: '3e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12', state: 'anomalous', candidate: { evidenceIds: ['obs-0001', 'obs-0002'] } })) } });
    const anomalous = makeCommand(anomalousFake).command;
    await anomalous.parseAsync(['node', 'aegishub', 'bounty', 'experiment', 'run', 'repo.private.contents-read-boundary.v1']);
    expect(anomalousFake.terminal.print).toHaveBeenCalledWith(expect.stringContaining('human validation'));
  });

  it('exposes inspect, export, and cooperative stop through injected services', async () => {
    const fake = services();
    const { command } = makeCommand(fake);
    await command.parseAsync(['node', 'aegishub', 'bounty', 'run', 'inspect', '3e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12']);
    await command.parseAsync(['node', 'aegishub', 'bounty', 'evidence', 'export', '3e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12', '--output', '/tmp/sanitized-pack']);
    await command.parseAsync(['node', 'aegishub', 'bounty', 'stop']);
    expect(fake.run.inspect).toHaveBeenCalled();
    expect(fake.evidence.export).toHaveBeenCalledWith('3e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12', '/tmp/sanitized-pack');
    expect(fake.stop.request).toHaveBeenCalled();
  });
});
