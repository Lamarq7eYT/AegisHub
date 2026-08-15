# AegisHub Phase 2 — local REST/GraphQL PoC

> Loopback-only demonstration using the checked-in fake GitHub server. It did not contact GitHub, use real credentials, or claim severity.

| Mode | Result | Requests | Mutations | Protected untrusted observations | Candidate | Candidate repetitions |
| --- | --- | ---: | ---: | ---: | --- | ---: |
| safe | expected | 5 | 0 | 0 | no | — |
| bypass | anomalous | 4 | 0 | 2 | yes | 2 |

The bypass case is synthetic and exists only to prove the high candidate threshold: two repeated protected marker disclosures are required, then the runner stops before the follow-up GraphQL operation. Cosmetic differences do not become candidates.
