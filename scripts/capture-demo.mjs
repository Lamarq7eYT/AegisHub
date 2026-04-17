import { execFileSync, spawn } from 'node:child_process';
import { mkdir, readdir, rename, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from '@playwright/test';

const rootUrl = 'http://127.0.0.1:4173';
const assetsDir = new URL('../docs/assets/', import.meta.url);
const assetsPath = fileURLToPath(assetsDir);

function run(command, args) {
  const executable = process.platform === 'win32' ? 'cmd.exe' : command;
  const executableArgs =
    process.platform === 'win32' ? ['/d', '/s', '/c', [command, ...args].join(' ')] : args;
  const child = spawn(executable, executableArgs, {
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  child.stdout.on('data', (chunk) => process.stdout.write(chunk));
  child.stderr.on('data', (chunk) => process.stderr.write(chunk));

  return child;
}

function stop(child) {
  if (!child.pid) {
    return;
  }

  if (process.platform === 'win32') {
    execFileSync('taskkill.exe', ['/pid', String(child.pid), '/t', '/f'], {
      stdio: 'ignore',
    });
    return;
  }

  child.kill('SIGTERM');
}

async function waitForServer(url, timeoutMs = 30000) {
  const startedAt = Date.now();

  while (Date.now() - startedAt < timeoutMs) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }

  throw new Error(`Timed out waiting for ${url}`);
}

const build = run('pnpm', ['--filter', '@aegishub/dashboard', 'build']);
const buildExitCode = await new Promise((resolve) => build.on('close', resolve));

if (buildExitCode !== 0) {
  process.exit(buildExitCode ?? 1);
}

const preview = run('pnpm', [
  '--filter',
  '@aegishub/dashboard',
  'exec',
  'vite',
  'preview',
  '--host',
  '127.0.0.1',
  '--port',
  '4173',
]);

try {
  await mkdir(assetsPath, { recursive: true });
  await waitForServer(rootUrl);

  const browser = await chromium.launch();
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    recordVideo: {
      dir: assetsPath,
      size: { width: 1440, height: 900 },
    },
  });
  const page = await context.newPage();
  const video = page.video();

  await page.goto(rootUrl, { waitUntil: 'networkidle' });
  await page.screenshot({ path: fileURLToPath(new URL('dashboard-preview.png', assetsDir)) });

  await page.getByRole('button', { name: /run demo scan/i }).click();
  await page.waitForTimeout(2200);
  await page.getByRole('button', { name: /ai fix/i }).first().click();
  await page.waitForTimeout(500);
  await page.screenshot({
    path: fileURLToPath(new URL('dashboard-finding-expanded.png', assetsDir)),
  });

  await context.close();
  const videoPath = await video?.path();
  if (videoPath) {
    const stableVideoPath = fileURLToPath(new URL('aegishub-demo.webm', assetsDir));
    await rm(stableVideoPath, { force: true });
    await rename(videoPath, stableVideoPath);

    try {
      execFileSync(
        'ffmpeg',
        [
          '-y',
          '-i',
          stableVideoPath,
          '-vf',
          'fps=12,scale=960:-1:flags=lanczos',
          '-loop',
          '0',
          fileURLToPath(new URL('aegishub-demo.gif', assetsDir)),
        ],
        { stdio: 'ignore' },
      );
    } catch {
      console.warn('ffmpeg is not available, skipping GIF generation');
    }
  }

  await browser.close();

  const generatedFiles = await readdir(assetsPath);
  await Promise.all(
    generatedFiles
      .filter((file) => file.startsWith('page@') && file.endsWith('.webm'))
      .map((file) => rm(new URL(file, assetsDir), { force: true })),
  );
} finally {
  stop(preview);
}
