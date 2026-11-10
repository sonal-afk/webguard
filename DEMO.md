# WebGuard demo script

A 3–4 minute walkthrough for a screen recording, the Kerala Science Congress
poster/oral session, or an interview. Everything runs on this laptop: the
"victim" is a local practice site that only *simulates* vulnerable responses
(no real database, files or shell commands), and it listens on 127.0.0.1 only.

---

## Before you start (5 minutes, once)

1. Double-click **`start_demo.bat`**. Two windows open (backend on port 5000,
   practice site on port 9000) and the browser opens the dashboard.
   Wait until the backend window prints `Model loaded` (about 6 seconds).
2. Log in at **`http://127.0.0.1:5000`** — use exactly this address, not
   `localhost`, or the extension won't share your login.
3. Chrome extension: open `chrome://extensions`, turn on **Developer mode**,
   click **Load unpacked** → choose the `webguard-extension` folder (or click
   ↻ reload if it's already installed). Pin it to the toolbar.
4. Check **Authorized Targets** lists `127.0.0.1:9000`. If not, add it and tick
   the ownership box.
5. Close unrelated tabs, set browser zoom to 110–125%, hide bookmarks bar.
   To record: **Win + Alt + R** (Xbox Game Bar) starts/stops recording.

---

## The demo (what to click, what to say)

### 1. The problem — 20 s
> "Most web apps get hacked through a few well-known flaws: SQL injection,
> cross-site scripting, path traversal. Professional scanners are expensive or
> hard to use, and they often blur watching a site with attacking it.
> WebGuard detects these flaws in real time, explains them in plain English,
> and only ever attacks sites you're authorised to test."

### 2. Static scan — 40 s
Paste into **URL / Endpoint** and click **⚡ Scan Now (Static)**:

```
http://127.0.0.1:9000/sqli?id=1' UNION SELECT username,password FROM users--
```

Point at: **VULNERABLE 95%**, **SQL Injection · CWE-89**, the AI panel on the
left (what the attacker gets + three fixes), and the similar real-world
examples underneath.

> "This step only reads the text — it never contacts the site. A fast rule
> engine catches the obvious cases in under a millisecond; anything ambiguous
> goes to a CodeBERT model I fine-tuned."

Then scan something harmless to show it isn't flagging everything:

```
http://shop.local/search?q=blue running shoes
```

Optional — show that URL-encoding doesn't hide an attack (the rules check the
decoded form too):

```
id=1%27%20OR%20%271%27%3D%271
```

Optional — show it doesn't cry wolf on a real name with an apostrophe:

```
https://shop.local/search?q=O'Brien
```

### 3. The browser extension — 40 s
Open the practice site in a new tab: `http://127.0.0.1:9000/sqli?id=1'`

> "While I browse, the extension watches URLs, forms and what the page
> shows. Here the page has leaked a database error, so it flags it — without
> sending a single attack request itself."

Click the extension icon to show the verdict and AI explanation.
(If the badge shows 🔒, you're not logged in at `127.0.0.1:5000`.)
**Rehearse this step once in your own Chrome before recording** — the backend
and dashboard were tested end to end, but the extension has to be checked in
Chrome itself.

### 4. Guided Deep Scan — 60 s
Back on the dashboard, in **🧭 Guided Deep Scan** enter
`http://127.0.0.1:9000/` → **🔎 Start Recon**.

> "Recon only discovers the pages and parameters — still no attacks."

Leave the defaults ticked → **▶ Run Selected Tests**. You get **8 findings**
in under a second: SQL injection, XSS, path traversal, command injection and
an open redirect.

> "Notice the safe page has zero findings — it escapes its output, and
> WebGuard correctly leaves it alone."

Open one finding → **▸ Show raw request / response** and point at the
**Reproduce: curl …** line.

> "Every finding comes with the exact request and response and a command
> anyone can run to reproduce it, so nothing has to be taken on trust.
> I review each one — Confirm, False positive, or Needs review."

Click **✓ Confirm** on two findings.

### 5. Report — 20 s
**📄 Continue to Report** → the HTML penetration-test report opens.
Scroll past the summary, one finding with its evidence, and the methodology.

### 6. Results and close — 30 s
> "On a 672-sample benchmark the system caught all 336 attacks with no false
> alarms. I don't fully trust that number, because I improved the rules after
> seeing what they missed, so I also tested on 80 new inputs, including normal
> code. The rules scored precision 1.0 and recall 0.98 there. That test also
> showed the AI model is overconfident on unfamiliar harmless input, so when
> only the model flags something, WebGuard says 'needs review' and the active
> scanner checks how the real server responds."

---

## Likely questions

| Question | Short answer |
|---|---|
| Isn't this a hacking tool? | It refuses to send a single request to any host not on your authorised list, and the extension never attacks anything. |
| Why both rules and ML? | Rules are instant and precise; the model catches some things the rules miss (e.g. an external URL in a generic `id=` parameter). But the model alone is wrong too often on unusual harmless input, so its solo detections are shown as "needs review", not "vulnerable". |
| Your benchmark says 100%. Isn't that suspicious? | Yes — the rules were improved after seeing their benchmark errors, so it isn't a blind test. That's why there's a second, independent set of 80 inputs (`benchmark/realistic_set.py`): rules precision 1.000, recall 0.977. Details: `benchmark/DEFENSE.md`. |
| How do you know the model isn't memorising? | Zero payload strings overlap between training and test sets — checked automatically when the corpus is built. |
| What does it still miss? | Attribute-injection XSS with no tag (`' autofocus onfocus='...`) on the independent set, and anything that can only be judged from the server's reaction — which active scanning provides. |
| What was the "needs review" verdict for? | On realistic harmless input (Jinja templates, `${...}` in JavaScript, "rock 'n' roll") the model said "malicious" with >99% confidence. No threshold fixes that, so the model can raise a flag but can't confirm one. |
| Does it use Gemini? | For explanations, if an API key is set; otherwise built-in expert text. Detection never depends on it. |
| Limitations? | Small, constructed benchmark (672 samples); SSRF is rule-only; tested on one laptop. |

---

## If something goes wrong live

| Symptom | Fix |
|---|---|
| Extension badge shows 🔒 | Log in at `http://127.0.0.1:5000` (not `localhost`). |
| "Unauthorized — please log in" after restarting | Restarting the backend logs everyone out; log in again. |
| Guided scan says target not authorised | Add `127.0.0.1:9000` under 🔐 Authorized Targets. |
| "Could not reach target" | The practice-site window was closed; run `start_demo.bat` again. |
| First ambiguous scan is slow | Wait for `Model loaded` in the backend window before starting. |

Don't click the **Open Redirect Test** link on the practice site during the
demo — it really does redirect you to example.com, which leaves the local
setup.
