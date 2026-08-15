import { Option, type Command } from 'commander';

import { BountyCliError, createBountyCliServices, type BountyCliServices } from './services.js';

export { BountyCliError } from './services.js';
export type { BountyCliServices } from './services.js';

export function registerBountyCommands(program: Command, services: BountyCliServices = createBountyCliServices()): Command {
  const bounty = program.command('bounty').description('Run safety-constrained security research workflows.');

  const policy = bounty.command('policy').description('Inspect the reviewed policy state.');
  policy.command('status').description('Show policy freshness and warnings.').action(async () => {
    await withTerminal(services, async () => {
      const status = await services.policy.status();
      services.terminal.print(`Policy ${status.state}: ${status.policyVersion}`);
      for (const warning of status.warnings) services.terminal.warn(warning);
    });
  });

  const auth = bounty.command('auth').description('Manage separate owner and researcher identities.');
  auth.command('login')
    .description('Authenticate one actor with GitHub Device Flow.')
    .addOption(new Option('--actor <actor>', 'owner or researcher').choices(['owner', 'researcher']))
    .option('--persist', 'store the credential in the native keyring')
    .action(async (options: { actor: 'owner' | 'researcher'; persist?: boolean }) => {
      await withTerminal(services, async () => {
        const result = await services.auth.login(options.actor, options.persist === true, async (verification) => {
          await services.terminal.showDeviceVerification?.(verification);
        });
        services.terminal.print(`Authenticated ${result.actor}: ${result.login} (immutable ID ${result.id})${result.persisted ? ' [keyring]' : ' [session-only]'}`);
      });
    });
  auth.command('status').description('Show configured actors without exposing credentials.').action(async () => {
    await withTerminal(services, async () => {
      const status = await services.auth.status();
      services.terminal.print(JSON.stringify(status));
    });
  });
  auth.command('logout').description('Delete one local actor record.').addOption(new Option('--actor <actor>', 'owner or researcher').choices(['owner', 'researcher'])).action(async (options: { actor: 'owner' | 'researcher' }) => {
    await withTerminal(services, async () => {
      await services.auth.logout(options.actor);
      services.terminal.print(`Logged out ${options.actor}.`);
    });
  });
  auth.command('revoke-local').description('Delete local records and show GitHub-side revocation guidance.').action(async () => {
    await withTerminal(services, async () => {
      const result = await services.auth.revokeLocal();
      services.terminal.print(`Local records revoked: ${result.revokedActors.join(', ')}.`);
      if (result.settingsUrl !== undefined) services.terminal.print(`Revoke the GitHub application separately at ${result.settingsUrl}.`);
    });
  });

  const lab = bounty.command('lab').description('Enroll and verify the owned lab.');
  lab.command('init').description('Initialize an owned repository lab.').argument('<owner/repository>').action(async (target: string) => {
    await withTerminal(services, async () => {
      const result = await services.lab.init(target);
      services.terminal.print(`Lab ${result.labId} initialized for repository ID ${result.repositoryId}.`);
    });
  });
  lab.command('verify').description('Verify identity, repository and marker state.').action(async () => {
    await withTerminal(services, async () => {
      const result = await services.lab.verify();
      services.terminal.print(`Lab verification: ${result.status}${result.labId === undefined ? '' : ` (${result.labId})`}.`);
    });
  });
  lab.command('status').description('Show local lab state.').action(async () => {
    await withTerminal(services, async () => {
      const result = await services.lab.status();
      services.terminal.print(`Lab status: ${result.status}${result.labId === undefined ? '' : ` (${result.labId})`}.`);
    });
  });

  const experiment = bounty.command('experiment').description('List, plan and run bounded experiments.');
  experiment.command('list').description('List bundled experiments.').action(async () => {
    await withTerminal(services, async () => {
      const experiments = await services.experiment.list();
      services.terminal.print(experiments.map((item) => `${item.id} v${item.version}`).join('\n'));
    });
  });
  experiment.command('plan').description('Plan without executing operations.').argument('<experiment-id>').action(async (id: string) => {
    await withTerminal(services, async () => {
      const plan = await services.experiment.plan(id);
      services.terminal.print(`Plan ${plan.planId} fingerprint ${plan.fingerprint}.`);
      services.terminal.print(`Operations: ${plan.operations.length}; budgets: ${JSON.stringify(plan.budgets)}.`);
    });
  });
  experiment.command('run').description('Replan and execute a bounded experiment.').argument('<experiment-id>').action(async (id: string) => {
    await withTerminal(services, async () => {
      const result = await services.experiment.run(id);
      if (result.state === 'anomalous') {
        services.terminal.print(`Candidate for human validation; evidence IDs: ${result.candidate?.evidenceIds.join(', ') ?? 'none'}.`);
      } else {
        services.terminal.print(`Experiment ${result.state}; run ${result.runId}.`);
      }
    });
  });

  const run = bounty.command('run').description('Inspect verified run evidence.');
  run.command('inspect').description('Verify schemas and checksums before display.').argument('<run-id>').action(async (runId: string) => {
    await withTerminal(services, async () => {
      const inspected = await services.run.inspect(runId);
      services.terminal.print(JSON.stringify(inspected));
    });
  });

  const evidence = bounty.command('evidence').description('Export sanitized evidence.');
  evidence.command('export').description('Export a verified analysis pack.').argument('<run-id>').requiredOption('--output <directory>').action(async (runId: string, options: { output: string }) => {
    await withTerminal(services, async () => {
      const result = await services.evidence.export(runId, options.output);
      services.terminal.print(`Sanitized evidence exported to ${result.path}.`);
    });
  });

  bounty.command('stop').description('Request cooperative cancellation of the active run.').action(async () => {
    await withTerminal(services, async () => {
      const result = await services.stop.request();
      services.terminal.print(result.requested ? 'Stop requested.' : 'No active run was changed.');
    });
  });

  return bounty;
}

async function withTerminal(services: BountyCliServices, action: () => Promise<void>): Promise<void> {
  try {
    await action();
  } catch (error) {
    if (error instanceof BountyCliError) throw error;
    throw new BountyCliError('bounty_command_failed', sanitizeErrorMessage(error));
  } finally {
    services.terminal.close();
  }
}

function sanitizeErrorMessage(error: unknown): string {
  if (!(error instanceof Error)) return 'Bounty command failed.';
  if (/gh[pousr]_\w+|github_pat_\w+|authorization:|cookie:/iu.test(error.message)) return 'Bounty command failed without exposing sensitive data.';
  return error.message;
}
