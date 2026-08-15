import { createHash } from 'node:crypto';

import { isJsonValue, type JsonObject, type JsonValue } from './contracts.js';

function compareJsonKeys(left: string, right: string): number {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

function sortJson(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    return value.map(sortJson);
  }

  if (value !== null && typeof value === 'object') {
    const sorted: JsonObject = Object.create(null) as JsonObject;
    for (const [key, child] of Object.entries(value).sort(([left], [right]) =>
      compareJsonKeys(left, right)
    )) {
      sorted[key] = sortJson(child);
    }
    return sorted;
  }

  return value;
}

export function stableJson(value: JsonValue): string {
  if (!isJsonValue(value)) {
    throw new TypeError('stableJson accepts only JSON-compatible values');
  }

  return JSON.stringify(sortJson(value));
}

export function sha256StableJson(value: JsonValue): string {
  return createHash('sha256').update(stableJson(value)).digest('hex');
}
