import { describe, expect, it } from 'vitest';

import { RateLimiterError, RunRateLimiter, type RuntimeClock } from '../src/transport/rate-limiter.js';

class ImmediateClock implements RuntimeClock {
  now = 0;
  sleeps: number[] = [];
  nowMs(): number { return this.now; }
  async sleep(ms: number, signal: globalThis.AbortSignal): Promise<void> {
    if (signal.aborted) throw new RateLimiterError('rate_wait_aborted');
    this.sleeps.push(ms);
    this.now += ms;
  }
}

describe('RunRateLimiter', () => {
  it('allows the configured burst, then waits for replenishment', async () => {
    const clock = new ImmediateClock();
    const limiter = new RunRateLimiter({ concurrency: 1, requestsPerSecond: 1, burst: 2, clock });

    await limiter.run(async () => 'one');
    await limiter.run(async () => 'two');
    await limiter.run(async () => 'three');

    expect(clock.sleeps).toEqual([1000]);
  });

  it('keeps at most one operation in flight', async () => {
    const clock = new ImmediateClock();
    const limiter = new RunRateLimiter({ concurrency: 1, requestsPerSecond: 1, burst: 2, clock });
    let inFlight = 0;
    let peak = 0;
    let releaseFirst!: () => void;
    const first = limiter.run(async () => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise<void>((resolve) => { releaseFirst = resolve; });
      inFlight -= 1;
      return 'first';
    });
    const second = limiter.run(async () => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      inFlight -= 1;
      return 'second';
    });

    await new Promise<void>((resolve) => globalThis.setImmediate(resolve));
    expect(peak).toBe(1);
    releaseFirst();
    await expect(first).resolves.toBe('first');
    await expect(second).resolves.toBe('second');
    expect(peak).toBe(1);
  });

  it('interrupts a queued wait on abort and runs nothing after emergency stop', async () => {
    const clock = new ImmediateClock();
    const limiter = new RunRateLimiter({ concurrency: 1, requestsPerSecond: 1, burst: 1, clock });
    const controller = new globalThis.AbortController();
    await limiter.run(async () => 'first');
    controller.abort();
    await expect(limiter.run(async () => 'never', controller.signal)).rejects.toMatchObject({ code: 'rate_wait_aborted' });

    limiter.stop();
    await expect(limiter.run(async () => 'never')).rejects.toMatchObject({ code: 'rate_limiter_stopped' });
  });

  it('keeps rate state isolated between limiter instances', async () => {
    const firstClock = new ImmediateClock();
    const secondClock = new ImmediateClock();
    const first = new RunRateLimiter({ concurrency: 1, requestsPerSecond: 1, burst: 1, clock: firstClock });
    const second = new RunRateLimiter({ concurrency: 1, requestsPerSecond: 1, burst: 1, clock: secondClock });

    await first.run(async () => 'first');
    await second.run(async () => 'second');

    expect(firstClock.sleeps).toEqual([]);
    expect(secondClock.sleeps).toEqual([]);
  });
});
