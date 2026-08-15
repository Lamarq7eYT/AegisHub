export interface RuntimeClock {
  nowMs(): number;
  sleep(ms: number, signal: globalThis.AbortSignal): Promise<void>;
}

export class RateLimiterError extends Error {
  constructor(readonly code: 'rate_wait_aborted' | 'rate_limiter_stopped' | 'rate_invalid_configuration') {
    super(code);
    this.name = 'RateLimiterError';
  }
}

export interface RunRateLimiterOptions {
  readonly concurrency: number;
  readonly requestsPerSecond: number;
  readonly burst: number;
  readonly clock?: RuntimeClock;
}

export class RunRateLimiter {
  readonly #requestsPerSecond: number;
  readonly #burst: number;
  readonly #clock: RuntimeClock;
  #availableTokens: number;
  #lastRefillMs: number;
  #tail: Promise<void> = Promise.resolve();
  #stopped = false;

  constructor(options: RunRateLimiterOptions) {
    if (!Number.isInteger(options.concurrency) || options.concurrency < 1 || options.concurrency > 1) {
      throw new RateLimiterError('rate_invalid_configuration');
    }
    if (!Number.isFinite(options.requestsPerSecond) || options.requestsPerSecond <= 0 || options.burst < 1) {
      throw new RateLimiterError('rate_invalid_configuration');
    }
    this.#requestsPerSecond = options.requestsPerSecond;
    this.#burst = options.burst;
    this.#clock = options.clock ?? new MonotonicRuntimeClock();
    this.#availableTokens = options.burst;
    this.#lastRefillMs = this.#clock.nowMs();
  }

  async run<T>(operation: () => Promise<T>, signal: globalThis.AbortSignal = new globalThis.AbortController().signal): Promise<T> {
    const execute = this.#tail.then(async () => {
      if (this.#stopped) throw new RateLimiterError('rate_limiter_stopped');
      if (signal.aborted) throw new RateLimiterError('rate_wait_aborted');
      await this.reserve(signal);
      if (this.#stopped) throw new RateLimiterError('rate_limiter_stopped');
      return operation();
    });
    this.#tail = execute.then(() => undefined, () => undefined);
    return execute;
  }

  stop(): void {
    this.#stopped = true;
  }

  private async reserve(signal: globalThis.AbortSignal): Promise<void> {
    while (true) {
      this.refill();
      if (this.#availableTokens >= 1) {
        this.#availableTokens -= 1;
        return;
      }
      const deficit = 1 - this.#availableTokens;
      const waitMs = Math.max(1, Math.ceil((deficit / this.#requestsPerSecond) * 1000));
      try {
        await this.#clock.sleep(waitMs, signal);
      } catch {
        throw new RateLimiterError('rate_wait_aborted');
      }
      if (this.#stopped) throw new RateLimiterError('rate_limiter_stopped');
      if (signal.aborted) throw new RateLimiterError('rate_wait_aborted');
    }
  }

  private refill(): void {
    const now = this.#clock.nowMs();
    const elapsed = Math.max(0, now - this.#lastRefillMs);
    this.#availableTokens = Math.min(this.#burst, this.#availableTokens + (elapsed / 1000) * this.#requestsPerSecond);
    this.#lastRefillMs = now;
  }
}

class MonotonicRuntimeClock implements RuntimeClock {
  nowMs(): number {
    return Math.floor(Number(process.hrtime.bigint() / 1_000_000n));
  }

  async sleep(ms: number, signal: globalThis.AbortSignal): Promise<void> {
    if (signal.aborted) throw new RateLimiterError('rate_wait_aborted');
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(resolve, ms);
      const abort = () => {
        globalThis.clearTimeout(timer);
        reject(new RateLimiterError('rate_wait_aborted'));
      };
      signal.addEventListener('abort', abort, { once: true });
    });
  }
}
