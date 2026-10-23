# RedBlue Sentinel

A secure sandbox for adversarial AI safety testing. Red teams run predefined attack
prompts in isolated sessions; blue teams detect, block and audit, with role separation
enforced on every screen.

**Live demo:** https://991122yrew.github.io/Ai-blue-and-red-security-/

## Features

- Isolated, short-lived test sessions
- Role-based access (Red, Blue, Admin) with denied attempts written to the audit log
- Deterministic risk scoring (Low / Medium / High)
- Live dashboard: attacks over time, result split, category mix, risk distribution
- Append-only audit log, SHA-256 hash-chained, with an integrity verifier and CSV export
- Rule-based anomaly detectors (bursts, category hammering, repeated misses, failed logins)

## Demo accounts

All simulated in the browser; password for all three is `demo1234`.

| Role  | Email          |
| ----- | -------------- |
| Red   | red@demo.io    |
| Blue  | blue@demo.io   |
| Admin | admin@demo.io  |

Quick tour: sign in as Red, run an injection test, try a Blue-only panel (the denial is
logged), switch to Blue, read the detections, then verify the audit chain.

## Run locally

It is a single static page, no build step:

```bash
python -m http.server 8000
```

Then open http://localhost:8000.

## Deploy

Pushing to `main` deploys to GitHub Pages through `.github/workflows/pages.yml`.
Enable it once under Settings → Pages → Source: GitHub Actions.

## Status

Demo-mode prototype: every test, result and audit entry is seeded or simulated in the
browser. There is no backend yet.
