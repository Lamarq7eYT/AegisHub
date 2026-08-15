# Bounty Mode Phase 1 — Live Gate Baseline

**Status:** Pending manual validation

The single pending gate requires the user to be present at the terminal with an already enrolled, directly owner-owned private lab repository. The run must use the current policy snapshot, a freshly verified lab marker, an interactive TTY, the configured public GitHub App client ID, and explicit typed confirmation of the repository identity and experiment fingerprint. The live gate must not enroll a new target, substitute another repository, or use credentials supplied in chat.

## Safe resume command

```bash
AEGISHUB_BOUNTY_LIVE=1 pnpm --filter @aegishub/bounty-runtime test:live
```

The test file is `packages/bounty-runtime/test/live/private-boundary.live.test.ts`. Normal CI and non-live test runs keep `AEGISHUB_BOUNTY_LIVE=0` or unset, so they do not contact GitHub or prompt for interactive authorization.

## Expected result

The user-present live validation is expected to perform Device Flow in-process for the owner and researcher identities, confirm that owner reads succeed while researcher and anonymous reads are denied, confirm that the owner repeat succeeds, classify the known-safe boundary as `expected`, and produce a sanitized evidence bundle. The bundle must pass schema, checksum, redaction, and absence-of-secret checks. No mutation or unverified target is permitted.

No password, cookie, two-factor code, access token, refresh token, reserve-account credential, or other secret should be sent in chat or stored in fixtures. If the user-owned lab, current policy, freshly verified marker, interactive terminal, or explicit confirmation is unavailable, leave this gate pending and do not claim full Phase 1 completion.
