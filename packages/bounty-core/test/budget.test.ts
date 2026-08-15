import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import {
  PHASE_ONE_BUDGET_CEILINGS,
  BudgetCounter,
  validateRequestedBudgets
} from '../src/budget.js';
import type { Budget } from '../src/contracts.js';

describe('Phase 1 budget ceilings', () => {
  it('defines the immutable Phase 1 ceiling', () => {
    expect(PHASE_ONE_BUDGET_CEILINGS).toEqual({
      concurrency: 1,
      requestsPerSecond: 1,
      burst: 2,
      maxRequests: 100,
      maxMutations: 10,
      timeoutMs: 20_000,
      maxReadRetries: 2,
      maxMutationRetries: 0
    });
  });

  it('accepts the ceiling and lower validated budgets', () => {
    const requested: Budget = {
      concurrency: 1,
      requestsPerSecond: 0.5,
      burst: 1,
      maxRequests: 12,
      maxMutations: 0,
      timeoutMs: 5_000,
      maxReadRetries: 1,
      maxMutationRetries: 0
    };

    expect(validateRequestedBudgets(requested)).toEqual(requested);
  });

  it.each([
    ['concurrency', { concurrency: 2 }],
    ['requestsPerSecond', { requestsPerSecond: 2 }],
    ['burst', { burst: 3 }],
    ['maxRequests', { maxRequests: 101 }],
    ['maxMutations', { maxMutations: 11 }],
    ['timeoutMs', { timeoutMs: 20_001 }],
    ['maxReadRetries', { maxReadRetries: 3 }],
    ['maxMutationRetries', { maxMutationRetries: 1 }]
  ] as const)('rejects a request above the %s ceiling', (_field, override) => {
    const requested = {
      ...PHASE_ONE_BUDGET_CEILINGS,
      ...override
    } as Budget;

    expect(() => validateRequestedBudgets(requested)).toThrow(/budget_ceiling_exceeded/);
  });
});

describe('BudgetCounter', () => {
  it('reserves requests and mutations atomically', () => {
    const counter = new BudgetCounter({ maxRequests: 2, maxMutations: 1 });

    expect(counter.tryReserve('mutation')).toEqual({ ok: true, ordinal: 1 });
    expect(counter.snapshot()).toEqual({ requests: 1, mutations: 1 });
    expect(counter.tryReserve('mutation')).toEqual({
      ok: false,
      reason: 'mutation_budget_exhausted'
    });
    expect(counter.snapshot()).toEqual({ requests: 1, mutations: 1 });
    expect(counter.tryReserve('read')).toEqual({ ok: true, ordinal: 2 });
    expect(counter.tryReserve('read')).toEqual({
      ok: false,
      reason: 'request_budget_exhausted'
    });
    expect(counter.snapshot()).toEqual({ requests: 2, mutations: 1 });
  });

  it('never exceeds either maximum under arbitrary reservation sequences', () => {
    fc.assert(
      fc.property(fc.array(fc.constantFrom<'read' | 'mutation'>('read', 'mutation')), (actions) => {
        const counter = new BudgetCounter({ maxRequests: 100, maxMutations: 10 });

        for (const action of actions) {
          counter.tryReserve(action);
          const snapshot = counter.snapshot();
          expect(snapshot.requests).toBeGreaterThanOrEqual(0);
          expect(snapshot.requests).toBeLessThanOrEqual(100);
          expect(snapshot.mutations).toBeGreaterThanOrEqual(0);
          expect(snapshot.mutations).toBeLessThanOrEqual(10);
        }
      })
    );
  });

  it('does not expose a decrement operation', () => {
    const counter = new BudgetCounter({ maxRequests: 1, maxMutations: 1 });

    expect('release' in counter).toBe(false);
    expect('decrement' in counter).toBe(false);
  });
});
