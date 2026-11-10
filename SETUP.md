# WebGuard Vulnerability Detector

WebGuard is a Flask-based web vulnerability scanner built around one rule:
**the app is the engine, the browser extension is a helper, and nothing gets
scanned without your explicit authorization.**

- Static payload/code analysis using attack patterns and optional ML inference
  — runs locally on text you paste in, never contacts a live target.
- An **Authorized Targets allowlist**: the app refuses to send a single real
  request to a host until you've explicitly added it and confirmed you own it
  or have permission to test it.
- A **Guided Deep Scan** workflow instead of a one-click "scan everything"
  button: Recon (discover params/forms — no payloads sent) → you pick which
  vulnerability classes and endpoints to test → targeted payloads run → you
  manually review each finding (raw request, raw response, and page-source
  context are shown so you can verify it yourself) → report.
- A browser dashboard at `http://127.0.0.1:5000`.
- A Chrome extension (`webguard-extension/`) that passively watches pages/forms
  for suspicious input in real time and flags them — it never fires payloads
  itself. When something looks worth a closer look, it hands off to the app
  ("Deep Scan in WebGuard" / "Authorize & Scan in WebGuard").
- Optional Gemini explanations when `GEMINI_API_KEY` is configured.

**Recommended workflow:** use the app as the main engine; use the extension
as a helper while you browse to notice interesting input in real time; never
trust an automated alert blindly — confirm findings yourself by checking the
request, response, and page source before relying on them.

Use this only on systems you own or have written permission to test. The app
will refuse to actively scan anything else.

## Quick Start

Simplest Windows start:

Double-click:

```text
run_webguard.bat
```

Or run:

```powershell
.\run_webguard.ps1
```

Then open `http://127.0.0.1:5000`.

Manual setup:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item webguard\.env.example webguard\.env
python webguard\backend.py
```

Open `http://127.0.0.1:5000` and log in with the values in `webguard/.env`.

Default local credentials are:

- Username: `admin`
- Password: `admin123`

Change `ADMIN_USER` and `ADMIN_PASSWORD` in `webguard/.env` before sharing or demoing the app.

## Optional ML Mode

The app works without the ML model. If model files are missing or ML packages are not installed, WebGuard falls back to pattern-only detection.

To enable ML fallback scanning:

```powershell
python -m pip install -r requirements-ml.txt
```

Then place a Hugging Face text-classification model directory at:

```text
webguard/web_vuln_model/
```

The directory should contain files such as `config.json`, `tokenizer.json`, and model weights.

## Optional Gemini Explanations

Add a Gemini key in `webguard/.env`:

```env
GEMINI_API_KEY=your_key_here
```

If no key is set, the app uses built-in explanations.

## Run the Demo Vulnerable Server

Never point the Guided Deep Scan at a real site while learning the tool.
Use the bundled demo target instead — it's intentionally vulnerable and
self-contained.

In a second terminal:

```powershell
.\.venv\Scripts\Activate.ps1
python webguard\vulnerable_test_server.py
```

It listens on `http://127.0.0.1:9000` with a SQLi endpoint (`/sqli`), a
reflected-XSS endpoint (`/xss`), a path-traversal endpoint (`/lfi`), a
simulated command-injection endpoint (`/cmdi`), an open-redirect endpoint
(`/redirect`), and a login form (`/login`) — enough surface to exercise every
vector the Guided Deep Scan supports.

To scan it from the dashboard:

1. Open `http://127.0.0.1:5000` and log in.
2. Click **🔐 Authorized Targets**, add `http://127.0.0.1:9000`, check the
   ownership confirmation box, and click Add — this is required before any
   live request is sent.
3. In **🧭 Guided Deep Scan**, enter `http://127.0.0.1:9000/` and click
   **Start Recon** (no payloads sent yet — just discovers params/forms/links).
4. Pick which vectors and discovered items to test, then **Run Selected
   Tests**.
5. For each finding, expand "Show raw request / response / source context"
   and check it yourself before marking it Confirmed / False Positive / Needs
   Review — don't trust the automated flag blindly.
6. Generate the report.

## Browser Extension

1. Start the Flask backend first.
2. Open Chrome and go to `chrome://extensions`.
3. Enable Developer mode.
4. Click Load unpacked.
5. Select `webguard-extension/`.

The extension only ever does local, passive analysis of URLs/forms/inputs as
you browse (plus a static pattern/ML check via the backend's `/api/analyze`,
which never contacts the page being checked). It never fires payloads at a
live target — when it flags something worth a closer look, its banner and
popup offer a handoff button that opens the dashboard's Guided Deep Scan for
that URL, gated by the same Authorized Targets allowlist as everywhere else.

## Important Files

- `webguard/backend.py`: Flask app, API routes, authentication, database setup, static analysis, the Authorized Targets allowlist, and the guided-scan (`/api/guided/*`) endpoints.
- `webguard/active_scan.py`: `discover()` (recon, no payloads) and `test_selection()` (targeted payload testing) that power the guided scan, plus a legacy `active_scan()` full-auto wrapper used by `/api/active_scan`.
- `webguard/llm.py`: Gemini integration plus fallback explanations.
- `webguard/report_generator.py`: HTML report generator, including raw request/response and analyst review status per finding.
- `webguard/templates/index.html`: Dashboard UI — static analysis, Authorized Targets panel, and the Guided Deep Scan stepper.
- `webguard/vulnerable_test_server.py`: intentionally vulnerable demo target for local testing.
- `webguard-extension/`: Chrome extension files — passive monitoring plus a handoff to the app, never active scanning on its own.

## Project Hygiene

Do not commit:

- `.env`
- virtual environments
- logs
- generated SQLite databases
- large datasets
- local model weights

Those are ignored in `.gitignore`.
