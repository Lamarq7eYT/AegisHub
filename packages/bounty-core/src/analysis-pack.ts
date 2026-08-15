import { analystInputSchema, type AnalystInput } from './contracts.js';

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) {
      deepFreeze(child);
    }
    Object.freeze(value);
  }

  return value;
}

export function buildAnalysisPack(input: AnalystInput): AnalystInput {
  const parsed = analystInputSchema.safeParse(input);
  if (!parsed.success) {
    throw new Error('invalid_analysis_pack');
  }

  return deepFreeze(parsed.data);
}
