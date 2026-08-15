import { describe, expect, it } from 'vitest';

const live = describe.skipIf(globalThis.process.env.AEGISHUB_BOUNTY_LIVE !== '1');

live('private contents boundary live validation', () => {
  it('requires explicit public app metadata, an enrolled local lab and an interactive terminal', () => {
    expect(globalThis.process.env.AEGISHUB_GITHUB_APP_CLIENT_ID?.trim()).toBeTruthy();
    expect(globalThis.process.stdin.isTTY).toBe(true);
    expect(globalThis.process.stdout.isTTY).toBe(true);
    throw new Error('live_gate_requires_user_present_and_freshly_verified_lab');
  });
});
