# WebGuard — Hybrid AI + Rule-Based Web Vulnerability Scanner

WebGuard finds web attacks such as **SQL injection, XSS, SSRF, path traversal, command injection and open redirect** by combining a fast rule engine with a fine-tuned **CodeBERT** model. Findings are mapped to CWE and the OWASP Top 10. *Co-authored IEEE-format research paper.*

**Safety first:** WebGuard refuses to send a single real request to a site until you add it to an allowlist and confirm you own it or have permission to test it.

## Components

- **Flask app** — the engine and dashboard (`http://127.0.0.1:5000`).
- **Chrome extension** — passively watches pages and forms while you browse and flags suspicious input. It never fires payloads itself; it hands off to the app.
- **Guided Deep Scan** — recon (no payloads) → you choose what to test → targeted payloads → you review the raw request and response for each finding → report.

## Results

| Test set | Engine | Precision | Recall |
|---|---|---|---|
| 672-sample benchmark | Rules | 100% | 96.4% |
| 672-sample benchmark | Rules + CodeBERT | 100% | 100% |
| **Independent 80-input set** (unseen payloads + tricky harmless inputs) | **Rules** | **100%** | **97.7%** |
| Independent 80-input set | Rules + CodeBERT | 78.6% | 100% |

**What I learned from these numbers:** the first CodeBERT model caught only 3.6% of attacks on a realistic benchmark. Retraining fixed that, but an independent test set showed it flagged harmless inputs like `<p>Hello {{ user.first_name }}</p>` with over 99% confidence. So a CodeBERT-only detection is reported as **"needs review"**, not "vulnerable". Rules confirm, the model raises candidates, and the active scanner settles them.

## Run it

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python webguard\backend.py
```

Full setup, the demo vulnerable server and ML mode: see [SETUP.md](SETUP.md). A 3–4 minute walkthrough: [DEMO.md](DEMO.md). Evaluation notes: [benchmark/DEFENSE.md](benchmark/DEFENSE.md).

Load the extension: Chrome → `chrome://extensions` → Developer mode → **Load unpacked** → select `webguard-extension/`.

⚠️ Only scan systems you own or have written permission to test.
