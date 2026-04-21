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

## Credit

When a report leads to a published GitHub Security Advisory, we will credit eligible reporters and remediation contributors in the advisory.
