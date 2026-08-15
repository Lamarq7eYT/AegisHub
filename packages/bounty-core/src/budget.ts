import { budgetSchema, type Budget } from './contracts.js';

export type BudgetSettings = Budget;

export const PHASE_ONE_BUDGET_CEILINGS: Readonly<BudgetSettings> = Object.freeze({
  concurrency: 1,
  requestsPerSecond: 1,
  burst: 2,
  maxRequests: 100,
  maxMutations: 10,
  timeoutMs: 20_000,
  maxReadRetries: 2,
  maxMutationRetries: 0
});

export type BudgetReservation =
  | { readonly ok: true; readonly ordinal: number }
  | {
      readonly ok: false;
      readonly reason: 'request_budget_exhausted' | 'mutation_budget_exhausted';
    };

function ceilingError(field: keyof BudgetSettings): Error {
  return new Error(`budget_ceiling_exceeded:${field}`);
}

export function validateRequestedBudgets(requested: BudgetSettings): BudgetSettings {
  for (const field of Object.keys(PHASE_ONE_BUDGET_CEILINGS) as Array<keyof BudgetSettings>) {
    const value = (requested as Partial<Record<keyof BudgetSettings, unknown>>)[field];
    const ceiling = PHASE_ONE_BUDGET_CEILINGS[field];
    if (typeof value === 'number' && value > ceiling) {
      throw ceilingError(field);
    }
  }

  const parsed = budgetSchema.safeParse(requested);
  if (!parsed.success) {
    throw new Error('invalid_budget_settings');
  }

  return Object.freeze({ ...parsed.data });
}

const counterSettingsSchema = budgetSchema.pick({
  maxRequests: true,
  maxMutations: true
});

type CounterSettings = Pick<BudgetSettings, 'maxRequests' | 'maxMutations'>;

export class BudgetCounter {
  readonly #maxRequests: number;
  readonly #maxMutations: number;
  #requests = 0;
  #mutations = 0;

  constructor(settings: CounterSettings) {
    const parsed = counterSettingsSchema.safeParse(settings);
    if (!parsed.success) {
      throw new Error('invalid_budget_counter_settings');
    }

    this.#maxRequests = parsed.data.maxRequests;
    this.#maxMutations = parsed.data.maxMutations;
  }

  tryReserve(kind: 'read' | 'mutation'): BudgetReservation {
    if (this.#requests >= this.#maxRequests) {
      return { ok: false, reason: 'request_budget_exhausted' };
    }

    if (kind === 'mutation' && this.#mutations >= this.#maxMutations) {
      return { ok: false, reason: 'mutation_budget_exhausted' };
    }

    this.#requests += 1;
    if (kind === 'mutation') {
      this.#mutations += 1;
    }

    return { ok: true, ordinal: this.#requests };
  }

  snapshot(): Readonly<{ requests: number; mutations: number }> {
    return Object.freeze({
      requests: this.#requests,
      mutations: this.#mutations
    });
  }
}
