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

## Demo highlights

- **Guided demo:** the "Run the 2-minute guided demo" button on the sign-in page signs in as Red, runs attacks
  until it has a blocked, a flagged and a missed result, switches to Blue and lands on the audit log.
- **Simulate tampering:** on the Audit Log, alters one entry in a throwaway copy and shows the hash chain
  catching it. The real log is never changed.
- **Create suggested rule:** open a MISSED run as Blue and add the recommended blocking rule in one click, then
  re-run the test as Red to see it caught.
- **Report:** Blue and Admin can download a CSV summary of the programme and every run from the dashboard.
- **Rule sandbox:** while creating or editing a rule, Blue sees live which of the 15 test cases it would match
  and which ones only this rule would newly catch, plus a check for invalid regexes.
- **Live activity feed:** the dashboard lists attacks as they land (refreshes every 5 s in Live API mode).
- **Idle session timeout:** 10 minutes without a click or key press signs you out, with a countdown chip and a
  warning in the last minute. Change it with `window.RB_SESSION_TTL_MIN` in `config.js` (0 turns it off).
  This is enforced in the browser; the API token itself expires after `TOKEN_TTL_MIN` (default 60).
- **Rate limiting:** the API allows 30 test runs per user per minute (`RUN_LIMIT_PER_MIN`), returns 429 beyond that
  and records `RATE_LIMITED` in the audit log.

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

## Accounts

- **Sign-up:** "New here? Create an account" on the sign-in page creates a Red Team account (10+ character password).
  Limited to `SIGNUPS_PER_HOUR` (default 5) per IP; set `ALLOW_SIGNUP=0` to turn it off.
- **Change password:** from the account menu. It signs out every other session (tokens issued earlier stop working).
- **Admin:** the Admin / Roles page can create users with any role, switch accounts off, and change roles.
- **First admin without demo accounts:** set `SEED_DEMO=0`, `ADMIN_EMAIL` and `ADMIN_PASSWORD`; the admin is created on
  startup if that email does not exist. When the demo accounts are off, the sign-in page hides the demo buttons.
- **Behind a proxy (Render):** set `TRUST_PROXY=1` so rate limits and audit entries use the real client IP from
  `X-Forwarded-For`. Only enable it behind a proxy you control.

## Two modes

The main site (`index.html`) detects a backend at startup:

- **Live API mode:** when served by `server/app.py` (or opened with `?api=https://your-api-host`),
  sign-in, test runs, rules, alerts, role management, audit log, chain verification and CSV
  export all go through the API. The sidebar shows "Live API" and data refreshes every 10 s.
- **Demo Mode:** with no reachable API (for example plain GitHub Pages), the original
  in-browser simulation runs unchanged, with seeded data that resets on reload.

`live.html` is a smaller console for exercising the API directly.

## Ideas still open

- Call a real LLM as the target model (needs your own API key, kept in a server environment variable).
- Use a hosted Postgres or a Render disk so data survives restarts.
- Keep the free Render service awake with an uptime pinger on `/api/health` before a demo.

## Known limits

- The audit view loads the newest 500 entries; the hash chain is verified server-side over all of them.
- The sandbox, target model and detectors are simulations; there is no real model behind the runs.
- Sessions live in memory (reload = sign in again); there is no refresh-token flow.

## Deploy the API (Render)

1. Sign in at https://render.com with GitHub, then **New → Blueprint** and pick this repo.
   `render.yaml` creates a free Docker web service with a generated `SECRET_KEY` and
   `CORS_ORIGIN` set to `https://991122yrew.github.io`.
2. When it is live, open `https://<your-service>.onrender.com/api/health`; it should return `{"status": "ok", ...}`.
3. Put that origin in `config.js`: `window.RB_API_URL = 'https://<your-service>.onrender.com';`, commit and push.
   GitHub Pages then runs in Live API mode.

Notes for a public deployment:

- The free plan's disk is ephemeral and the service sleeps when idle (first request takes ~30 s),
  so the SQLite database resets on restart. Use a paid plan with a disk (`DB_PATH=/data/sentinel.db`) to keep data.
- The one-click demo buttons use the public demo password, so anyone can sign in as Admin.
  Fine for a hackathon demo; for anything real set `SEED_DEMO=0` and create real users.
