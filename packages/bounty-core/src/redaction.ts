import { createHmac, randomBytes } from 'node:crypto';

import { isJsonValue, type JsonObject, type JsonValue } from './contracts.js';

export type RedactionKind =
  | 'authorization'
  | 'cookie'
  | 'token'
  | 'device-code'
  | 'user-code'
  | 'signed-link'
  | 'secret'
  | 'email'
  | 'personal-identifier'
  | 'value';

export interface RedactionAllowlist {
  readonly retainedFields?: readonly string[];
  readonly retainedValuePatterns?: readonly RegExp[];
}

interface DetectionPattern {
  readonly kind: RedactionKind;
  readonly pattern: RegExp;
}

const detectionPatterns: readonly DetectionPattern[] = [
  { kind: 'authorization', pattern: /\bAuthorization\s*:\s*[^\r\n]+/gi },
  { kind: 'cookie', pattern: /\bCookie\s*:\s*[^\r\n]+/gi },
  {
    kind: 'device-code',
    pattern: /\bdevice_code\s*[=:]\s*["']?[^\s&"'<>]+/gi
  },
  {
    kind: 'user-code',
    pattern: /\buser_code\s*[=:]\s*["']?[^\s&"'<>]+/gi
  },
  {
    kind: 'signed-link',
    pattern:
      /\b(?:X-Amz-Signature|X-Amz-Credential|Signature|sig|signature)\s*=\s*["']?[^\s&"'<>]+/gi
  },
  {
    kind: 'token',
    pattern: /\b(?:ghp_|github_pat_|ghu_|ghs_|ghr_|ghe_)[A-Za-z0-9_]+/g
  },
  { kind: 'token', pattern: /\br1\.[A-Za-z0-9._-]+/g },
  {
    kind: 'token',
    pattern: /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b/g
  },
  {
    kind: 'email',
    pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi
  }
];

const sensitiveFieldPattern =
  /(?:authorization|cookie|password|passphrase|secret|token|credential|api[-_]?key|private[-_]?key|device[-_]?code|user[-_]?code|csrf|session|signature|signed[-_]?url)/i;

function placeholder(kind: RedactionKind, digest: string): string {
  return `[REDACTED:${kind}:${digest}]`;
}

function matchesAllowlist(value: string, patterns: readonly RegExp[] | undefined): boolean {
  if (patterns === undefined) {
    return false;
  }

  return patterns.some((pattern) => {
    const safePattern = new RegExp(pattern.source, pattern.flags.replace('g', ''));
    return safePattern.test(value);
  });
}

export class RunRedactor {
  readonly #key: Uint8Array;
  #destroyed = false;

  private constructor(key: Uint8Array) {
    this.#key = key;
  }

  static create(): RunRedactor {
    return new RunRedactor(randomBytes(32));
  }

  redactJson(value: JsonValue, policy?: RedactionAllowlist): JsonValue {
    this.assertUsable();
    if (!isJsonValue(value)) {
      throw new Error('invalid_json_value');
    }

    return this.#redactJsonValue(value, policy, '');
  }

  redactText(value: string, kindHint: RedactionKind = 'value'): string {
    this.assertUsable();
    let output = value;

    for (const detection of detectionPatterns) {
      output = output.replace(detection.pattern, (match) =>
        placeholder(detection.kind, this.#digest(detection.kind, match))
      );
    }

    if (kindHint !== 'value' && output === value && value.length > 0) {
      output = placeholder(kindHint, this.#digest(kindHint, value));
    }

    return output;
  }

  assertNoSuspectedSecret(value: string, allowlist: readonly RegExp[] = []): void {
    this.assertUsable();
    const findings: string[] = [];

    for (const detection of detectionPatterns) {
      const safePattern = new RegExp(detection.pattern.source, detection.pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = safePattern.exec(value)) !== null) {
        if (!matchesAllowlist(match[0], allowlist)) {
          findings.push(detection.kind);
        }
        if (match[0].length === 0) {
          safePattern.lastIndex += 1;
        }
      }
    }

    if (findings.length > 0) {
      throw new Error(`suspected_secret:${[...new Set(findings)].sort().join(',')}`);
    }
  }

  destroy(): void {
    if (!this.#destroyed) {
      this.#key.fill(0);
      this.#destroyed = true;
    }
  }

  #redactJsonValue(value: JsonValue, policy: RedactionAllowlist | undefined, path: string): JsonValue {
    if (typeof value === 'string') {
      return this.redactText(value);
    }

    if (Array.isArray(value)) {
      return value.map((item, index) =>
        this.#redactJsonValue(item, policy, `${path}[${index}]`)
      );
    }

    if (value === null || typeof value !== 'object') {
      return value;
    }

    const output: JsonObject = {};
    for (const [key, child] of Object.entries(value)) {
      const childPath = path === '' ? key : `${path}.${key}`;
      const allowlisted = this.isAllowlisted(childPath, child, policy);
      if (allowlisted) {
        output[key] = child;
        continue;
      }

      if (typeof child === 'string' && sensitiveFieldPattern.test(key)) {
        output[key] = placeholder(this.kindForField(key), this.#digest(this.kindForField(key), child));
      } else {
        output[key] = this.#redactJsonValue(child, policy, childPath);
      }
    }

    return output;
  }

  #digest(kind: RedactionKind, value: string): string {
    return createHmac('sha256', this.#key)
      .update(kind)
      .update('\0')
      .update(value)
      .digest('hex')
      .slice(0, 12);
  }

  #isDestroyed(): boolean {
    return this.#destroyed;
  }

  private assertUsable(): void {
    if (this.#isDestroyed()) {
      throw new Error('redactor_destroyed');
    }
  }

  private isAllowlisted(path: string, value: JsonValue, policy: RedactionAllowlist | undefined): boolean {
    if (policy?.retainedFields?.includes(path) !== true || typeof value !== 'string') {
      return false;
    }

    return matchesAllowlist(value, policy.retainedValuePatterns);
  }

  private kindForField(field: string): RedactionKind {
    const normalized = field.toLowerCase();
    if (normalized.includes('authorization')) return 'authorization';
    if (normalized.includes('cookie')) return 'cookie';
    if (normalized.includes('device')) return 'device-code';
    if (normalized.includes('user')) return 'user-code';
    if (normalized.includes('signature') || normalized.includes('signed')) return 'signed-link';
    if (normalized.includes('password') || normalized.includes('secret') || normalized.includes('key')) {
      return 'secret';
    }
    return 'token';
  }
}
