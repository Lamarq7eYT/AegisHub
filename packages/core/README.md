# @aegishub/core

High-performance Rust analysis engine for AegisHub. The crate currently implements:

- `Analyzer` trait for isolated analyzers.
- `SecretsAnalyzer` with pattern-based and Shannon entropy detection.
- Security score computation from findings.
- Native binary `aegishub-engine` that reads scan input as JSON from stdin and writes a JSON report to stdout.
- Optional WASM export behind the `wasm` feature.

## Build

```bash
cargo build --release
```

The native binary is emitted as `target/release/aegishub-engine`.

## Test

```bash
cargo test
```

## Native JSON Input

```json
{
  "repo": "owner/repo",
  "commit": "abc123",
  "files": [
    {
      "path": "src/config.js",
      "language": "javascript",
      "content": "const token = process.env.TOKEN;"
    }
  ]
}
```

## Native JSON Output

```json
{
  "repo": "owner/repo",
  "commit": "abc123",
  "scanned_at": "2026-04-17T00:00:00Z",
  "score": 100,
  "findings": [],
  "stats": {
    "files_scanned": 1,
    "lines_scanned": 1,
    "duration_ms": 1
  }
}
```

## WASM

```bash
wasm-pack build --target web -- --features wasm
```

The exported `scan_content(source, language)` function returns a JavaScript value containing a scan report for a single in-memory source file.
