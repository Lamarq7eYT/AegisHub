# Contributing

## Setup

Install Node 20, pnpm, and the stable Rust toolchain.

```bash
pnpm install
pnpm lint
pnpm test
pnpm build
```

For the Rust core:

```bash
cd packages/core
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## Branching

Use short feature branches:

```text
feature/<scope>
fix/<scope>
docs/<scope>
```

## Commits

Use Conventional Commits:

```text
feat(core): add secret entropy detector
fix(cli): handle failed scan status
docs: describe responsible disclosure
```
