# AegisHub Demo

This demo is designed for GitHub community submissions and recruiter review. It shows the product flow without requiring a live GitHub App installation.

Created by Llew with care, effort, and dedication.

## Demo Storyboard

1. Open the dashboard demo.
2. Press `Run demo scan`.
3. Show the score ring and metrics updating from scan state to completed state.
4. Filter findings by `Critical` or `High`.
5. Expand `AI fix` for the first finding.
6. Show the pull request comment preview.

## Local Run

```bash
pnpm install
pnpm --filter @aegishub/dashboard dev
```

Open the Vite URL printed in the terminal.

## Recording

Use a 1440 by 900 browser window for the cleanest README preview. A short 10 to 15 second clip works best:

```text
Dashboard loaded -> Run demo scan -> Expand AI fix -> PR comment preview
```

## Automated Capture

The `capture:demo` script starts the dashboard, captures screenshots, records a short WebM clip, and writes a GIF when `ffmpeg` is available.

```bash
pnpm capture:demo
```

Generated assets are written to `docs/assets/`.
