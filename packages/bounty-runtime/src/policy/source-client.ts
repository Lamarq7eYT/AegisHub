import { createHash } from 'node:crypto';
import { TextEncoder } from 'node:util';

import type { PolicySourceResult } from '@aegishub/bounty-core';

export const POLICY_SOURCE_URLS = Object.freeze([
  'https://bounty.github.com/rules.html',
  'https://bounty.github.com/scope.html',
  'https://bounty.github.com/targets.html',
  'https://bounty.github.com/ineligible.html',
  'https://bounty.github.com/rewards.html'
] as const);

export const POLICY_SOURCES = Object.freeze([
  Object.freeze({ id: 'rules', url: POLICY_SOURCE_URLS[0] }),
  Object.freeze({ id: 'scope', url: POLICY_SOURCE_URLS[1] }),
  Object.freeze({ id: 'targets', url: POLICY_SOURCE_URLS[2] }),
  Object.freeze({ id: 'ineligible', url: POLICY_SOURCE_URLS[3] }),
  Object.freeze({ id: 'rewards', url: POLICY_SOURCE_URLS[4] })
] as const);

export const MAX_POLICY_SOURCE_BODY_BYTES = 2_000_000;
export const POLICY_SOURCE_TIMEOUT_MS = 20_000;

export type PolicySourceUrl = (typeof POLICY_SOURCE_URLS)[number];
export type PolicySourceId = (typeof POLICY_SOURCES)[number]['id'];
export type PolicySourceMalformedReason = Extract<
  PolicySourceResult,
  { state: 'malformed' }
>['reason'];

interface PolicyAbortSignal {
  readonly aborted: boolean;
  addEventListener(type: 'abort', listener: () => void, options?: { readonly once?: boolean }): void;
  removeEventListener(type: 'abort', listener: () => void): void;
}

export interface PolicyFetchResponse {
  readonly status: number;
  text(): Promise<string>;
}

export interface PolicyFetchOptions {
  readonly redirect: 'manual';
  readonly credentials: 'omit';
  readonly headers: Readonly<Record<string, never>>;
  readonly signal: PolicyAbortSignal;
}

export type PolicyFetch = (url: PolicySourceUrl, options: PolicyFetchOptions) => Promise<PolicyFetchResponse>;

interface PolicyAbortController {
  readonly signal: PolicyAbortSignal;
  abort(): void;
}

export interface PolicySourceClientDependencies {
  readonly fetch: PolicyFetch;
  readonly now: () => Date;
  readonly createAbortController: () => PolicyAbortController;
  readonly setTimeout: (callback: () => void, delayMs: number) => unknown;
  readonly clearTimeout: (timer: unknown) => void;
}

export interface FetchPolicySourceInput {
  readonly sourceId: PolicySourceId;
  readonly url: PolicySourceUrl;
  readonly expectedSha256: string;
  readonly dependencies: PolicySourceClientDependencies;
}

export class PolicySourceContentError extends Error {
  constructor(readonly code: PolicySourceMalformedReason) {
    super(code);
    this.name = 'PolicySourceContentError';
  }
}

export class PolicySourceInputError extends Error {
  constructor(readonly code: 'invalid_policy_source_input') {
    super(code);
    this.name = 'PolicySourceInputError';
  }
}

interface HtmlTag {
  readonly name: string;
  readonly closing: boolean;
  readonly selfClosing: boolean;
  readonly start: number;
  readonly end: number;
}

interface ValidatedFetchInput {
  readonly sourceId: PolicySourceId;
  readonly url: PolicySourceUrl;
  readonly expectedSha256: string;
  readonly dependencies: PolicySourceClientDependencies;
  readonly checkedAt: Date;
  readonly controller: PolicyAbortController;
}

type OperationOutcome<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: unknown };

const textEncoder = new TextEncoder();
const emptyHeaders: Readonly<Record<string, never>> = Object.freeze({});
const blockElements = new Set([
  'address',
  'article',
  'aside',
  'blockquote',
  'div',
  'dl',
  'fieldset',
  'figcaption',
  'figure',
  'footer',
  'form',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'header',
  'hr',
  'li',
  'main',
  'nav',
  'ol',
  'p',
  'pre',
  'section',
  'table',
  'tr',
  'ul'
]);
const volatileElements = new Set(['script', 'style', 'nav', 'footer']);
const namedEntities: Readonly<Record<string, string>> = Object.freeze({
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' ',
  eacute: 'é'
});

export function canonicalizePolicyHtml(html: string): string {
  if (typeof html !== 'string') {
    throw new PolicySourceContentError('invalid-normalized-content');
  }
  if (textEncoder.encode(html).byteLength > MAX_POLICY_SOURCE_BODY_BYTES) {
    throw new PolicySourceContentError('source-too-large');
  }

  const mainContent = selectSingleMain(html);
  const normalized = normalizeText(extractText(mainContent));
  if (normalized.length === 0) {
    throw new PolicySourceContentError('empty-normalized-content');
  }
  return normalized;
}

export function hashCanonicalPolicyHtml(html: string): string {
  return createHash('sha256').update(canonicalizePolicyHtml(html), 'utf8').digest('hex');
}

export async function fetchPolicySource(input: FetchPolicySourceInput): Promise<PolicySourceResult> {
  const validated = validateFetchInput(input);
  const setTimeout = validated.dependencies.setTimeout;
  const clearTimeout = validated.dependencies.clearTimeout;
  const fetch = validated.dependencies.fetch;
  let timer: unknown;
  try {
    timer = setTimeout(() => {
      validated.controller.abort();
    }, POLICY_SOURCE_TIMEOUT_MS);
  } catch {
    throw new PolicySourceInputError('invalid_policy_source_input');
  }

  const outcome = await captureOutcome<PolicySourceResult>(async (): Promise<PolicySourceResult> => {
    let response: PolicyFetchResponse;
    try {
      response = await fetch(validated.url, {
        redirect: 'manual',
        credentials: 'omit',
        headers: emptyHeaders,
        signal: validated.controller.signal
      });
    } catch {
      return unavailable(validated);
    }

    if (!isPolicyFetchResponse(response)) {
      throw new PolicySourceInputError('invalid_policy_source_input');
    }
    if (response.status >= 300 && response.status < 400) {
      return malformed(validated, 'redirect-response');
    }
    if (response.status < 200 || response.status >= 300) {
      return malformed(validated, 'http-error-response');
    }

    let body: string;
    try {
      body = await response.text();
    } catch {
      return unavailable(validated);
    }

    try {
      const observedSha256 = hashCanonicalPolicyHtml(body);
      return {
        sourceId: validated.sourceId,
        state: observedSha256 === validated.expectedSha256 ? 'match' : 'changed',
        checkedAt: validated.checkedAt,
        observedSha256
      };
    } catch (error) {
      if (error instanceof PolicySourceContentError) {
        return malformed(validated, error.code);
      }
      throw error;
    }
  });
  try {
    clearTimeout(timer);
  } catch {
    throw new PolicySourceInputError('invalid_policy_source_input');
  }
  if (outcome.ok) {
    return outcome.value;
  }
  throw outcome.error;
}

async function captureOutcome<T>(operation: () => Promise<T>): Promise<OperationOutcome<T>> {
  try {
    return { ok: true, value: await operation() };
  } catch (error) {
    return { ok: false, error };
  }
}

function unavailable(input: ValidatedFetchInput): PolicySourceResult {
  return { sourceId: input.sourceId, state: 'unavailable', checkedAt: input.checkedAt };
}

function malformed(input: ValidatedFetchInput, reason: PolicySourceMalformedReason): PolicySourceResult {
  return { sourceId: input.sourceId, state: 'malformed', checkedAt: input.checkedAt, reason };
}

function validateFetchInput(input: unknown): ValidatedFetchInput {
  const inputData = readDataRecord(input, ['sourceId', 'url', 'expectedSha256', 'dependencies']);
  if (inputData === undefined) {
    throw new PolicySourceInputError('invalid_policy_source_input');
  }
  const { sourceId, url, expectedSha256 } = inputData;
  const source =
    typeof sourceId === 'string' && typeof url === 'string' ? findKnownSource(sourceId, url) : undefined;
  const dependencies = readDependencies(inputData.dependencies);
  if (
    source === undefined ||
    typeof expectedSha256 !== 'string' ||
    !isExpectedSha256(expectedSha256) ||
    dependencies === undefined
  ) {
    throw new PolicySourceInputError('invalid_policy_source_input');
  }

  let checkedAt: Date;
  let controller: PolicyAbortController;
  try {
    const now = dependencies.now;
    const createAbortController = dependencies.createAbortController;
    checkedAt = now();
    controller = createAbortController();
  } catch {
    throw new PolicySourceInputError('invalid_policy_source_input');
  }
  if (!isValidDate(checkedAt) || !isAbortController(controller)) {
    throw new PolicySourceInputError('invalid_policy_source_input');
  }

  return {
    sourceId: source.id,
    url: source.url,
    expectedSha256,
    dependencies,
    checkedAt,
    controller
  };
}

function selectSingleMain(html: string): string {
  let index = 0;
  let mainCount = 0;
  let mainDepth = 0;
  let contentStart = -1;
  let contentEnd = -1;

  while (index < html.length) {
    const tagStart = html.indexOf('<', index);
    if (tagStart < 0) {
      break;
    }
    if (html.startsWith('<!--', tagStart) && html.indexOf('-->', tagStart + 4) < 0) {
      if (mainDepth > 0) {
        throw new PolicySourceContentError('malformed-main');
      }
      break;
    }
    const tag = readHtmlTag(html, tagStart);
    if (tag === undefined) {
      if (looksLikeMainMarker(html, tagStart)) {
        throw new PolicySourceContentError('malformed-main');
      }
      index = tagStart + 1;
      continue;
    }
    index = tag.end;
    if (!tag.closing && (tag.name === 'script' || tag.name === 'style')) {
      const rawTextEnd = skipRawTextElement(html, tag.name, index);
      if (rawTextEnd === undefined) {
        if (mainDepth > 0) {
          throw new PolicySourceContentError('invalid-normalized-content');
        }
        break;
      }
      index = rawTextEnd;
      continue;
    }
    if (tag.name !== 'main') {
      continue;
    }
    if (tag.closing) {
      if (mainDepth === 0) {
        throw new PolicySourceContentError('malformed-main');
      }
      mainDepth -= 1;
      if (mainDepth === 0) {
        contentEnd = tag.start;
      }
      continue;
    }

    if (tag.selfClosing) {
      throw new PolicySourceContentError('malformed-main');
    }

    mainCount += 1;
    if (mainCount > 1) {
      throw new PolicySourceContentError('multiple-main');
    }
    mainDepth += 1;
    contentStart = tag.end;
  }

  if (mainCount === 0) {
    throw new PolicySourceContentError('missing-main');
  }
  if (mainDepth !== 0 || contentStart < 0 || contentEnd < contentStart) {
    throw new PolicySourceContentError('malformed-main');
  }
  return html.slice(contentStart, contentEnd);
}

function extractText(html: string): string {
  let index = 0;
  let output = '';
  const suppressed: string[] = [];

  while (index < html.length) {
    const tagStart = html.indexOf('<', index);
    if (tagStart < 0) {
      if (suppressed.length === 0) {
        output += html.slice(index);
      }
      break;
    }
    if (suppressed.length === 0) {
      output += html.slice(index, tagStart);
    }
    const tag = readHtmlTag(html, tagStart);
    if (tag === undefined) {
      if (suppressed.length === 0) {
        output += '<';
      }
      index = tagStart + 1;
      continue;
    }
    index = tag.end;

    if (suppressed.length > 0) {
      if (!tag.closing && volatileElements.has(tag.name)) {
        suppressed.push(tag.name);
      } else if (tag.closing && tag.name === suppressed[suppressed.length - 1]) {
        suppressed.pop();
      }
      continue;
    }
    if (!tag.closing && volatileElements.has(tag.name)) {
      suppressed.push(tag.name);
    } else if ((tag.closing && blockElements.has(tag.name)) || (!tag.closing && tag.name === 'br')) {
      output += '\n';
    }
  }

  if (suppressed.length > 0) {
    throw new PolicySourceContentError('invalid-normalized-content');
  }
  return output;
}

function normalizeText(text: string): string {
  const decoded = decodeEntities(text).normalize('NFC').replace(/\r\n?/gu, '\n');
  return decoded
    .replace(/[\t\f\v \u00a0]+/gu, ' ')
    .replace(/ *\n */gu, '\n')
    .replace(/\n+/gu, '\n')
    .trim();
}

function decodeEntities(text: string): string {
  return text.replace(/&(#(?:[xX][^;]*|[^;]*)|[a-z][a-z0-9]*);/giu, (entity, reference: string) => {
    if (reference.startsWith('#')) {
      const hexadecimal = reference[1]?.toLowerCase() === 'x';
      const digits = reference.slice(hexadecimal ? 2 : 1);
      const validDigits = hexadecimal ? /^[0-9a-f]+$/iu.test(digits) : /^[0-9]+$/u.test(digits);
      if (digits.length === 0 || !validDigits) {
        throw new PolicySourceContentError('invalid-normalized-content');
      }
      const value = Number.parseInt(digits, hexadecimal ? 16 : 10);
      if (
        !Number.isSafeInteger(value) ||
        value < 0 ||
        value > 0x10ffff ||
        (value >= 0xd800 && value <= 0xdfff)
      ) {
        throw new PolicySourceContentError('invalid-normalized-content');
      }
      return String.fromCodePoint(value);
    }
    return namedEntities[reference.toLowerCase()] ?? entity;
  });
}

function readHtmlTag(html: string, start: number): HtmlTag | undefined {
  if (html.startsWith('<!--', start)) {
    const commentEnd = html.indexOf('-->', start + 4);
    return commentEnd < 0
      ? undefined
      : { name: '', closing: false, selfClosing: false, start, end: commentEnd + 3 };
  }
  let cursor = start + 1;
  let closing = false;
  if (html[cursor] === '/') {
    closing = true;
    cursor += 1;
  }
  const nameStart = cursor;
  if (cursor >= html.length || !isAsciiLetter(html[cursor]!)) {
    return undefined;
  }
  cursor += 1;
  while (cursor < html.length && isTagNameCharacter(html[cursor]!)) {
    cursor += 1;
  }
  const name = html.slice(nameStart, cursor).toLowerCase();
  const delimiter = html[cursor];
  if (delimiter === undefined || (!isWhitespace(delimiter) && delimiter !== '/' && delimiter !== '>')) {
    return undefined;
  }
  let quote: '"' | "'" | undefined;
  let attributeState: 'between' | 'name' | 'before-value' | 'quoted-value' | 'unquoted-value' = 'between';
  let selfClosing = false;
  for (; cursor < html.length; cursor += 1) {
    const character = html[cursor]!;
    if (quote !== undefined) {
      if (character === quote) {
        quote = undefined;
        attributeState = 'between';
      }
      continue;
    }
    if (character === '"' || character === "'") {
      if (attributeState === 'between' || attributeState === 'before-value') {
        quote = character;
        attributeState = 'quoted-value';
      } else if (attributeState !== 'unquoted-value') {
        return undefined;
      }
    } else if (character === '>') {
      return { name, closing, selfClosing, start, end: cursor + 1 };
    } else if (closing) {
      if (!isWhitespace(character)) {
        return undefined;
      }
    } else if (isWhitespace(character)) {
      if (attributeState === 'name' || attributeState === 'unquoted-value') {
        attributeState = 'between';
      }
    } else if (character === '/') {
      if (attributeState === 'between' || attributeState === 'name') {
        selfClosing = true;
        attributeState = 'between';
      }
    } else if (character === '=') {
      if (attributeState !== 'name') {
        return undefined;
      }
      selfClosing = false;
      attributeState = 'before-value';
    } else if (attributeState === 'between') {
      if (selfClosing) {
        return undefined;
      }
      attributeState = 'name';
    } else if (attributeState === 'before-value') {
      attributeState = 'unquoted-value';
    }
  }
  return undefined;
}

function looksLikeMainMarker(html: string, start: number): boolean {
  return /^<\/?main(?:[\s/>]|$)/iu.test(html.slice(start));
}

function skipRawTextElement(html: string, name: 'script' | 'style', start: number): number | undefined {
  let index = start;
  while (index < html.length) {
    const tagStart = html.indexOf('<', index);
    if (tagStart < 0) {
      return undefined;
    }
    const tag = readHtmlTag(html, tagStart);
    if (tag === undefined) {
      index = tagStart + 1;
      continue;
    }
    if (tag.closing && tag.name === name) {
      return tag.end;
    }
    index = tag.end;
  }
  return undefined;
}

function isAsciiLetter(value: string): boolean {
  return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
}

function isTagNameCharacter(value: string): boolean {
  return isAsciiLetter(value) || (value >= '0' && value <= '9') || value === '-' || value === ':';
}

function isWhitespace(value: string): boolean {
  return value === ' ' || value === '\t' || value === '\n' || value === '\r' || value === '\f';
}

function findKnownSource(
  sourceId: string,
  url: string
): (typeof POLICY_SOURCES)[number] | undefined {
  return POLICY_SOURCES.find((source) => source.id === sourceId && source.url === url);
}

function isExpectedSha256(value: string): boolean {
  return /^[a-f0-9]{64}$/u.test(value);
}

function readDependencies(value: unknown): PolicySourceClientDependencies | undefined {
  const data = readDataRecord(value, ['fetch', 'now', 'createAbortController', 'setTimeout', 'clearTimeout']);
  if (
    data === undefined ||
    typeof data.fetch !== 'function' ||
    typeof data.now !== 'function' ||
    typeof data.createAbortController !== 'function' ||
    typeof data.setTimeout !== 'function' ||
    typeof data.clearTimeout !== 'function'
  ) {
    return undefined;
  }
  return {
    fetch: data.fetch as PolicyFetch,
    now: data.now as () => Date,
    createAbortController: data.createAbortController as () => PolicyAbortController,
    setTimeout: data.setTimeout as (callback: () => void, delayMs: number) => unknown,
    clearTimeout: data.clearTimeout as (timer: unknown) => void
  };
}

function isAbortController(value: unknown): value is PolicyAbortController {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  try {
    const controller = value as { abort?: unknown; signal?: unknown };
    const signal = controller.signal;
    return (
      typeof controller.abort === 'function' &&
      typeof signal === 'object' &&
      signal !== null &&
      typeof (signal as { aborted?: unknown }).aborted === 'boolean' &&
      typeof (signal as { addEventListener?: unknown }).addEventListener === 'function' &&
      typeof (signal as { removeEventListener?: unknown }).removeEventListener === 'function'
    );
  } catch {
    return false;
  }
}

function isPolicyFetchResponse(value: unknown): value is PolicyFetchResponse {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  try {
    const response = value as { status?: unknown; text?: unknown };
    return (
      typeof response.status === 'number' &&
      Number.isSafeInteger(response.status) &&
      typeof response.text === 'function'
    );
  } catch {
    return false;
  }
}

function isValidDate(value: unknown): value is Date {
  return value instanceof Date && Number.isFinite(value.getTime());
}

function readDataRecord(value: unknown, expectedKeys: readonly string[]): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null) {
    return undefined;
  }
  try {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      return undefined;
    }
    const ownKeys = Reflect.ownKeys(value);
    if (
      ownKeys.length !== expectedKeys.length ||
      ownKeys.some((key) => typeof key !== 'string' || !expectedKeys.includes(key))
    ) {
      return undefined;
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const data: Record<string, unknown> = {};
    for (const key of expectedKeys) {
      const descriptor = descriptors[key];
      if (descriptor === undefined || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        return undefined;
      }
      data[key] = descriptor.value;
    }
    return data;
  } catch {
    return undefined;
  }
}
