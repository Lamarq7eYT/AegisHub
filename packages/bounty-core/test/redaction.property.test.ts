import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { RunRedactor } from '../src/redaction.js';
import type { JsonValue } from '../src/contracts.js';

const tokenSecrets = [
  'ghp_fixture_personal_1234567890',
  'github_pat_fixture_personal_1234567890',
  'ghu_fixture_user_1234567890',
  'ghs_fixture_server_1234567890',
  'ghr_fixture_refresh_1234567890',
  'ghe_fixture_enterprise_1234567890',
  'r1.fixture_refresh_1234567890',
  'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.fixture-signature'
] as const;

describe('RunRedactor', () => {
  it('redacts supported credential, cookie, code, signed-link, email, and entropy forms', () => {
    const redactor = RunRedactor.create();
    const deviceCode = 'device_fixture_code_1234567890';
    const userCode = 'ABCD-1234';
    const signedValue = 'signed_fixture_value_1234567890';
    const email = 'fixture.user@example.test';
    const input = [
      'Authorization: Bearer ghp_fixture_personal_1234567890',
      'Cookie: session=github_pat_fixture_personal_1234567890',
      `device_code=${deviceCode} user_code=${userCode}`,
      `https://github.example.test/callback?X-Amz-Signature=${signedValue}`,
      `contact=${email}`,
      ...tokenSecrets.slice(2)
    ].join('\n');

    const output = redactor.redactText(input);

    for (const secret of [
      ...tokenSecrets,
      deviceCode,
      userCode,
      signedValue,
      email
    ]) {
      expect(output).not.toContain(secret);
    }
    expect(output).toMatch(/\[REDACTED:[a-z-]+:[0-9a-f]{12}\]/);
  });

  it('redacts nested JSON values based on field names and content', () => {
    const redactor = RunRedactor.create();
    const secret = 'ghp_fixture_nested_1234567890';
    const input: JsonValue = {
      headers: {
        Authorization: `Bearer ${secret}`,
        Cookie: 'session=fixture_cookie_1234567890'
      },
      credentials: {
        password: 'fixture-password-1234567890',
        clientSecret: 'fixture-client-secret-1234567890',
        accessToken: secret
      },
      request: {
        email: 'fixture.user@example.test',
        signedUrl: 'https://github.example.test/path?Signature=fixture-signature-1234567890'
      },
      nested: [{ device_code: 'device_fixture_1234567890' }]
    };

    const output = redactor.redactJson(input);
    const serialized = JSON.stringify(output);

    expect(serialized).not.toContain(secret);
    expect(serialized).not.toContain('fixture-password-1234567890');
    expect(serialized).not.toContain('fixture-client-secret-1234567890');
    expect(serialized).not.toContain('fixture.user@example.test');
    expect(serialized).not.toContain('fixture-signature-1234567890');
    expect(serialized).not.toContain('device_fixture_1234567890');
  });

  it('uses equal placeholders for equal values in one run but not across runs', () => {
    const first = RunRedactor.create();
    const second = RunRedactor.create();
    const secret = 'ghp_fixture_equal_1234567890';
    const firstOutput = first.redactText(`${secret}|${secret}`, 'token');
    const [left, right] = firstOutput.split('|');
    const secondOutput = second.redactText(secret, 'token');

    expect(left).toBe(right);
    expect(left).not.toBe(secret);
    expect(secondOutput).not.toBe(left);
  });

  it('fails closed after destroying the run-local key', () => {
    const redactor = RunRedactor.create();
    redactor.destroy();

    expect(() => redactor.redactText('fixture')).toThrow('redactor_destroyed');
    expect(() => redactor.redactJson({ value: 'fixture' })).toThrow('redactor_destroyed');
  });

  it('reports a suspected secret without echoing the secret in the error', () => {
    const redactor = RunRedactor.create();
    const secret = 'ghp_fixture_error_1234567890';

    try {
      redactor.assertNoSuspectedSecret(`unsafe=${secret}`);
      throw new Error('expected secret detector to throw');
    } catch (error) {
      expect(String(error)).not.toContain(secret);
      expect(String(error)).toContain('suspected_secret');
    }
  });

  it('redacts a generated secret at arbitrary nested JSON paths', () => {
    const pathArbitrary = fc.array(
      fc.constantFrom('outer', 'nested', 'payload', 'headers', 'metadata'),
      { minLength: 1, maxLength: 5 }
    );
    const suffixArbitrary = fc.array(fc.constantFrom('a', 'b', 'c', '7', '9'), {
      minLength: 20,
      maxLength: 32
    });

    fc.assert(
      fc.property(pathArbitrary, suffixArbitrary, (path, suffix) => {
        const secret = `ghp_fixture_${suffix.join('')}`;
        let value: JsonValue = secret;
        for (const key of [...path].reverse()) {
          value = { [key]: value };
        }

        const output = JSON.stringify(RunRedactor.create().redactJson(value));
        expect(output).not.toContain(secret);
      })
    );
  });
});
