# Security

The canonical security policy lives at the repository root: [SECURITY.md](../SECURITY.md).

## Reporting a vulnerability

Please do not open a public issue for suspected vulnerabilities. Use GitHub's private vulnerability reporting flow from the repository Security tab:

<https://github.com/LlewxamDev/AegisHub/security/advisories/new>

For a GitHub product candidate discovered under the official program, use the official Bug Bounty process and its private submission channel. Public issues are not a disclosure channel for security findings.

## Bounty Mode boundary

Bounty Mode active tests are restricted to a verified, directly owner-owned private lab and use two separate identities controlled by the operator. Tests are low-volume, catalog-bound and policy-gated. Do not test repositories, organizations, accounts or data that you do not own or explicitly control. A candidate is not automatically a vulnerability, a severity rating or a submission.

Never paste passwords, tokens, refresh tokens, cookies, 2FA codes, private keys or client secrets into issues, reports, AI prompts or fixtures. Evidence bundles are sanitized and should be treated as review artifacts, not as a place to store raw API responses or PII.

For operational details, see [BOUNTY_MODE.md](./BOUNTY_MODE.md). For the implementation invariants, see the [approved design](./superpowers/specs/2026-08-13-bounty-mode-foundation-design.md).

## Handling secrets

Do not commit credentials, tokens, private keys or production configuration values. Use local `.env` files and native secret managers for sensitive values. `.env.example` contains only public application metadata and a non-live flag; it intentionally contains no secret or token field.

## Responsible disclosure

Include affected versions, reproduction steps using local test data, expected impact and suggested mitigation in a private report. Limit any response data to the minimum necessary and redact textual evidence. For an AegisHub defect, use the repository's private security contact and never use a public issue to disclose details.
