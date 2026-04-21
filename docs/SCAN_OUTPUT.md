# Scan Output Contract

AegisHub findings should be predictable enough for the CLI, dashboard, CI jobs, and future export formats to consume the same scan result without guessing field names.

## Finding Shape

```json
{
  "id": "secret.generic_api_key",
  "analyzer": "SecretsAnalyzer",
  "severity": "high",
  "confidence": "medium",
  "path": "src/config.ts",
  "line": 12,
  "column": 18,
  "message": "Possible API key committed to source control.",
  "remediation": "Move the secret to a private secret store and rotate the exposed value."
}
```

## Required Fields

| Field | Purpose |
| --- | --- |
| `id` | Stable rule identifier for filtering, tests, and suppressions. |
| `analyzer` | Analyzer that produced the finding. |
| `severity` | Impact level: `low`, `medium`, `high`, or `critical`. |
| `confidence` | Signal quality: `low`, `medium`, or `high`. |
| `path` | Repository-relative file path when available. |
| `message` | Human-readable explanation of the risk. |
| `remediation` | Short actionable fix suggestion. |

## Optional Location Fields

`line` and `column` should be included when the analyzer can identify the exact source location. If an analyzer only knows the file-level location, it should omit those fields rather than returning placeholder values.

## Severity Guidance

- `critical`: likely exploitable credential or unsafe pattern with immediate production impact.
- `high`: strong secret/security signal that should block merge until reviewed.
- `medium`: suspicious pattern that needs human review.
- `low`: weak signal, metadata, or hygiene issue.

## Confidence Guidance

Use `confidence` to separate impact from certainty. For example, an entropy-based secret candidate may be `high` severity but `medium` confidence until confirmed by pattern context.

Refs #1.
