# Security Policy

The canonical security policy lives at the repository root: [`SECURITY.md`](../SECURITY.md).

## Reporting a Vulnerability

Please do not open a public issue for suspected vulnerabilities. Use GitHub's private vulnerability reporting flow from the repository Security tab:

<https://github.com/Lamarq7eYT/AegisHub/security/advisories/new>

Include affected versions, reproduction steps, impact, and any suggested fixes.

We will acknowledge reports within 72 hours and keep reporters updated during triage and remediation.

## Handling Secrets

Do not commit credentials, tokens, private keys, or production configuration values. Use local `.env` files and secret managers for sensitive values.
