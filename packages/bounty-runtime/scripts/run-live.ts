import { spawn } from 'node:child_process';
import { resolve } from 'node:path';

const workspaceRoot = resolve(import.meta.dirname, '..', '..', '..');

if (globalThis.process.stdin.isTTY !== true || globalThis.process.stdout.isTTY !== true) {
  globalThis.process.stderr.write('live_gate_requires_interactive_tty\n');
  globalThis.process.exitCode = 1;
} else {
  const child = spawn(
    'pnpm',
    ['exec', 'vitest', 'run', 'test/live/private-boundary.live.test.ts'],
    {
      cwd: resolve(workspaceRoot, 'packages/bounty-runtime'),
      env: {
        ...globalThis.process.env,
        AEGISHUB_BOUNTY_LIVE: '1',
        AEGISHUB_BOUNTY_LIVE_TTY_ASSERTED: '1'
      },
      stdio: 'inherit'
    }
  );

  child.on('error', () => {
    globalThis.process.exitCode = 1;
  });
  child.on('exit', (code, signal) => {
    globalThis.process.exitCode = code ?? (signal === null ? 1 : 1);
  });
}
