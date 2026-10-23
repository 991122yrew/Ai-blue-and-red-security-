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

## Real backend (`server/`)

A zero-dependency Python 3.9+ API (standard library only) with persistent storage.

```bash
python server/app.py              # http://127.0.0.1:8000  (site at /, live console at /live.html)
python -m unittest discover -s server -v
```

- **Auth:** scrypt password hashes, HMAC-signed bearer tokens, lockout after 5 failed logins in 5 minutes
- **RBAC on every route:** a denied request returns 403 and is written to the audit log
- **Red/Blue separation:** Red never receives rule names, ids or counts; Blue's audit view hides admin entries
- **Audit log:** SQLite, SHA-256 hash-chained, with triggers that block UPDATE/DELETE; `GET /api/audit/verify` recomputes the chain
- **Anomaly detectors:** bursts, category hammering, repeated misses, access-denied and failed-login spikes
- **Admin:** user activation and roles, CSV export (formula-injection safe)

| Endpoint | Roles |
| --- | --- |
| `POST /api/auth/login`, `GET /api/me`, `GET /api/health` | any |
| `GET /api/tests`, `GET /api/runs`, `GET /api/metrics` | all (Red sees only its own) |
| `POST /api/runs` | red, admin |
| `GET/POST/PATCH /api/rules` | blue, admin |
| `GET /api/audit`, `/api/audit/verify`, `GET /api/alerts`, `POST /api/alerts/{id}/ack` | blue, admin |
| `GET /api/audit/export.csv`, `GET/PATCH /api/users` | admin |

Configuration (environment variables): `HOST`, `PORT`, `DB_PATH`, `SECRET_KEY`,
`TOKEN_TTL_MIN`, `CORS_ORIGIN`, `SEED_DEMO=0` to skip creating the demo accounts, and
`DEMO_PASSWORD`. **For any public deployment set `SECRET_KEY` and `DEMO_PASSWORD`, or
`SEED_DEMO=0`.** A `Dockerfile` is included.

To use the console from the GitHub Pages site, open
`live.html?api=https://your-api-host` (the API must be deployed separately).

## Status

- The main site (`index.html`) is still the original in-browser demo with simulated data.
- `live.html` is wired to the real API. Porting every screen of the main site to the API
  is the next step.
