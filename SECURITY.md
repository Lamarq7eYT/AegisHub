# Security Policy

## Supported Versions

AegisHub is in early development. Security fixes target the default branch first and are included in the next public release.

| Version | Supported |
| --- | --- |
| main | Yes |
| 0.1.x | Best effort |

## Reporting a Vulnerability

Please do not open a public issue for suspected vulnerabilities.

Use GitHub's private vulnerability reporting flow from the repository Security tab:

<https://github.com/Lamarq7eYT/AegisHub/security/advisories/new>

Include as much detail as possible:

- affected package, command, or workflow;
- affected version, commit, or branch;
- reproduction steps using local test data;
- expected impact and attacker requirements;
- suggested fix or mitigation, if you have one.

We aim to acknowledge reports within 72 hours and will keep reporters updated while triage and remediation are in progress.

## Scope

In scope:

- AegisHub CLI scanning behavior;
- Rust analysis engine parsing and report generation;
- GitHub API integration logic;
- GitHub Actions workflows and release automation;
- dependency or supply-chain issues that affect AegisHub users.

Out of scope:

- social engineering;
- denial-of-service against GitHub or third-party services;
- issues requiring leaked credentials or access to someone else's account;
- findings that only affect local development without a plausible security impact.

## Bounty Mode research boundary

Bounty Mode is a controlled research workbench, not an autonomous bounty finder. Active tests are limited to low-volume experiments against a verified private repository directly owned by the operator, using separate owner and researcher accounts. Do not test repositories, organizations, accounts or data that you do not own or explicitly control. A candidate result is not automatically a vulnerability, severity assessment or submission.

Never paste passwords, access tokens, refresh tokens, cookies, 2FA codes, private keys or client secrets into issues, reports, AI prompts or fixtures. Public issues are not a disclosure channel for security findings. For GitHub product candidates, use GitHub's official Bug Bounty process and its private channel. For AegisHub itself, use this repository's private security contact and GitHub Security Advisories.

The normal test suite uses synthetic identities and a loopback fake server. The live gate is opt-in, requires the user present with an already enrolled owned lab, and must never be replaced with a third-party target. Evidence is sanitized before persistence and must not contain raw secrets or PII.

## Credit

When a report leads to a published GitHub Security Advisory, we will credit eligible reporters and remediation contributors in the advisory.
