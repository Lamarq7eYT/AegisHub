import type { PolicySourceResult } from '@aegishub/bounty-core';

export const POLICY_SOURCE_URLS = [
  'https://bounty.github.com/rules.html',
  'https://bounty.github.com/scope.html',
  'https://bounty.github.com/targets.html',
  'https://bounty.github.com/ineligible.html',
  'https://bounty.github.com/rewards.html'
] as const;

export const POLICY_SOURCES = [
  { id: 'rules', url: POLICY_SOURCE_URLS[0] },
  { id: 'scope', url: POLICY_SOURCE_URLS[1] },
  { id: 'targets', url: POLICY_SOURCE_URLS[2] },
  { id: 'ineligible', url: POLICY_SOURCE_URLS[3] },
  { id: 'rewards', url: POLICY_SOURCE_URLS[4] }
] as const;

export const MAX_POLICY_SOURCE_BODY_BYTES = 2_000_000;
export const POLICY_SOURCE_TIMEOUT_MS = 20_000;

export type PolicySourceUrl = (typeof POLICY_SOURCE_URLS)[number];
export type PolicySourceId = (typeof POLICY_SOURCES)[number]['id'];
export type PolicySourceMalformedReason = Extract<
  PolicySourceResult,
  { state: 'malformed' }
>['reason'];

export interface PolicyFetchResponse {
  readonly status: number;
  text(): Promise<string>;
}

export interface PolicyFetchOptions {
  readonly redirect: 'manual';
  readonly credentials: 'omit';
  readonly headers: Readonly<Record<string, never>>;
  readonly signal: AbortSignal;
}

export type PolicyFetch = (url: PolicySourceUrl, options: PolicyFetchOptions) => Promise<PolicyFetchResponse>;

export interface PolicySourceClientDependencies {
  readonly fetch: PolicyFetch;
  readonly now: () => Date;
  readonly createAbortController: () => AbortController;
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

export class PolicySourceClientError extends Error {
  constructor(readonly code: 'unimplemented_policy_source_client') {
    super(code);
    this.name = 'PolicySourceClientError';
  }
}

export class PolicySourceInputError extends Error {
  constructor(readonly code: 'invalid_policy_source_input') {
    super(code);
    this.name = 'PolicySourceInputError';
  }
}

export function canonicalizePolicyHtml(_html: string): string {
  throw new PolicySourceClientError('unimplemented_policy_source_client');
}

export function hashCanonicalPolicyHtml(_html: string): string {
  throw new PolicySourceClientError('unimplemented_policy_source_client');
}

export async function fetchPolicySource(_input: FetchPolicySourceInput): Promise<PolicySourceResult> {
  throw new PolicySourceClientError('unimplemented_policy_source_client');
}
