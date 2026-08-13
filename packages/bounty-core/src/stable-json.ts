import { createHash } from 'node:crypto';

import { isJsonValue, type JsonObject, type JsonValue } from './contracts.js';

function sortJson(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    return value.map(sortJson);
  }

  if (value !== null && typeof value === 'object') {
    const sorted: JsonObject = Object.create(null) as JsonObject;
    for (const key of Object.keys(value).sort()) {
      sorted[key] = sortJson(value[key]);
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
