# Defense Sheet — WebGuard IEEE Paper

Purpose: for every non-obvious claim in `webguard_ieee_paper.tex`, this maps
the claim to the exact file/line or artifact that produced it, and gives you
the one-sentence answer to "how do you know that?" Read this before you
present or defend the paper. If a reviewer or examiner asks about a number,
find it here, then go look at the actual file — don't just recite this sheet.

---

## November 2026: rule revision and the "needs review" verdict (read this first)

Some of the sections below describe the system *before* this revision and are
kept as the history of how it got here. Where they disagree, this section wins.

**What changed in `webguard/backend.py`:**
- Inputs are now checked in several normalised forms: percent-decoded once
  and twice (`%2527`), HTML-entity-decoded, and with SQL `/**/` comments
  removed (`_normalised_variants()`).
- Rules about *parameter values* (`PARAM_VALUE`) only fire on user input
  (`?id=`, `&q=`, a form body line), not on ordinary code. This is what lets
  the engine flag `id=1'` (a value that *ends* in a quote) without flagging
  `q=O'Brien`.
- Open redirect now compares the redirect target with the host of the pasted
  URL / `Host:` header (`_external_redirect_targets()`), replacing the old
  hard-coded `.example/.test` exception.
- Rules that fired on normal code were narrowed: `$(...)` (jQuery), `${...}`
  (JS template literals), `{{ }}`/`{% %}` (ordinary templates),
  `time.sleep()`, `subprocess.run([...])` without `shell=True`, regex `.exec()`.
- Mitigations (prepared statements, `htmlspecialchars()`, ...) now cancel only
  their own category and require call syntax, so typing "parameterized" into
  a URL no longer switches detection off.
- **A detection made by CodeBERT alone is now `verdict: NEEDS_REVIEW`
  (`vulnerable: false, needs_review: true`), not VULNERABLE.** Reason below.

**Results** (`benchmark/results.json`; the old file is kept as
`results_before_rule_revision.json`):

| | Precision | Recall |
|---|---|---|
| Rules, 672-sample benchmark (before → after) | 1.000 → 1.000 | 0.625 → 0.964 |
| Hybrid (anything flagged), 672-sample benchmark | 1.000 → 1.000 | 0.970 → 1.000 |
| Rules, independent 80-input set (before → after) | 0.676 → 1.000 | 0.523 → 0.977 |
| Rules + CodeBERT, independent 80-input set | 0.786 | 1.000 |

**"Isn't 1.000 on the benchmark suspicious?"** Yes, and say so. The rules
were revised *after* looking at what they missed on `eval_set.csv`, so the
benchmark is no longer a blind test for the rules. That is why
`benchmark/realistic_set.py` exists: 44 attacks with payloads and hosts not
in the benchmark, and 36 deliberately awkward harmless inputs (apostrophes in
names, jQuery, JS template literals, Jinja templates, Python code). Its
"before" numbers were measured *before* any rule was changed. Two rules were
then tightened after seeing false alarms on it (`'#` must be followed by
space/end, so jQuery `'#id'` doesn't match; a quote only counts if it ends
the value, so `q=5' 10"` doesn't match), so it is not perfectly blind either —
state that honestly. Run it yourself: `python benchmark/realistic_set.py`.

**"Why is the model's solo verdict only 'needs review'?"** On the
independent set, CodeBERT called 12 of 36 harmless inputs malicious — e.g.
`<p>Hello {{ user.first_name }}</p>`, `` `Hello ${user.name}` ``,
`q=rock 'n' roll` — every one with >99% confidence. Its correct catches
also score >99%, so no confidence threshold separates them. The benchmark
hid this because its benign samples are all simple `?page=3&sort=price`
URLs. So: rules confirm, the model raises candidates, and the active scanner
(which watches the real server response) settles them.

**What the rules still miss:** on the benchmark, 12 open-redirect samples
that put an external URL in a generic parameter (`id=`, `q=`, `user=`) —
deliberately not flagged, because `?ref=https://google.com` is normal;
CodeBERT flags them for review. On the independent set, attribute-injection
XSS with no tag (`' autofocus onfocus='alert(1)`).

---

## "Why does the paper separate passive observation from active probing?"

Because they have different legal/ethical status. Reading a page you loaded
in your own browser sends nothing to the target — it's not an attack. Sending
a crafted payload is unsolicited traffic against someone else's server, and
doing that without permission is a computer-crime issue in most
jurisdictions (see the Legal Disclaimer in
`webguard/report_generator.py` and the Authorized Targets allowlist in
`webguard/backend.py`). The extension (`webguard-extension/content.js`,
`background.js`) never sends a payload — go check: there is no `fetch()`
or `XMLHttpRequest` call in `content.js` that sends anything to the page
being observed, only `chrome.runtime.sendMessage` to the extension's own
background script.

## "Why doesn't the extension show a 'safe' verdict?"

Because passive observation only proves the *presence* of evidence, never
its *absence*. Not seeing a SQL error doesn't mean there isn't one — you
just didn't trigger it. See `content.js`'s neutral banner text: "watching —
nothing flagged yet (not a scan)" — deliberately not "page is safe."

## "Where does Table I (CWE/OWASP mapping) come from?"

Direct transcription of `webguard/backend.py`'s `WEB_PATTERNS` dict (each
category's `'cwe'` key) and `active_scan.py`'s per-finding `'cwe'` fields,
cross-referenced against the public OWASP Top 10 2021 and MITRE CWE
lists (both cited: `\cite{owasp}`, `\cite{cwe}`). This is not learned or
estimated — it's a lookup table you can read directly in the source.

## "How does the curl reproduction line work, and why is it safe?"

`active_scan.py`'s `_build_curl()` function. Every value that goes into the
command is passed through Python's `shlex.quote()`, which wraps it in single
quotes so that shell metacharacters (`;`, `|`, `` ` ``) inside an attack
payload can't break out and run as a second, unintended shell command when
pasted into a terminal.

## "What is `vulnerabilities.db` and is it used to evaluate the model?"

No. It's a 21,897-row SQLite table of historical code-level vulnerability
records (columns: `code`, `cwe`, `language`, `source`, `project`) used
*operationally* by `search_similar()` in `backend.py` — when a finding is
confirmed, it looks up similar past vulnerabilities to show as context. It
is never used for training or for the classification metrics in Section
"Evaluation and Discussion." The paper says this explicitly. If asked "did
you evaluate on 21,897 samples?" — the answer is no, and the paper does not
claim that.

## "Why can't you report the original training metrics for the CodeBERT model?"

Because the vulnerable-sample half of the training CSV no longer exists in
the repository — only `datasets/safe_samples.csv` remains, and it is 100%
label=0 (6,000 benign rows, zero vulnerable rows: verified by loading it and
checking `df["label"].value_counts()`). The original `training_history.json`
shows validation accuracy/F1/AUC of 1.0 at epoch 1 — a near-certain sign of
an easily-separable dataset, not evidence of a strong generalizing model.
Rather than restate that unverifiable 1.0 or the paper's old, unsupported
96.4%/94.2% figures, we built a new evaluation corpus from scratch (see
below) and reported what that actually measures.

## "How was the 672-sample evaluation corpus built? Is it legitimate?"

`benchmark/build_dataset.py`. Two halves:
- **336 benign** rows: sampled (fixed seed 42, deduplicated) from
  `datasets/safe_samples.csv` — the same benign corpus the model trained on.
- **336 malicious** rows: WebGuard's own real attack payloads
  (`active_scan.py`'s `SQL_PAYLOADS`, `XSS_PAYLOADS`, `PATH_PAYLOADS`,
  `CMD_PAYLOADS`, `REDIRECT_PAYLOADS` — imported directly, not retyped) plus
  hand-authored canonical examples for SSRF/XXE/SSTI/hardcoded-credentials
  (each checked against the exact regex in `backend.py`'s `WEB_PATTERNS`
  so ground truth is unambiguous), each embedded into 4 request-shape
  templates, in 3 forms: canonical, percent-encoded, case/whitespace-mangled.

This is legitimate as a *transparent, internal characterization* — not as a
claim of state-of-the-art generalization. The paper says this explicitly
(see "Evaluation Corpus" subsection, the tautology caveat). If a reviewer
asks "is this a fair benchmark against other tools?" — no, and the paper
doesn't claim that either; it benchmarks WebGuard's own pipeline against
itself, honestly, on data whose construction is fully disclosed.

## "How were the actual numbers in Tables III/IV/V produced?"

`benchmark/run_benchmark.py`. It **imports** `webguard/backend.py` as a
module and calls the real functions — `detect_patterns()`,
`has_safe_pattern()`, `analyze()`, and the actual loaded CodeBERT pipeline
via `get_vulnerability_detector()`. It does not reimplement any detection
logic. Confusion matrices (TP/TN/FP/FN) are computed directly from
predictions vs. the ground-truth `label` column in `eval_set.csv`. Results
are saved to `benchmark/results.json` — every number in the paper's tables
traces to a field in that file. If asked to reproduce: run
`python benchmark/build_dataset.py` then `python benchmark/run_benchmark.py`
from the `webguard/.venv` environment.

## "Why was CodeBERT-alone recall so low (0.009 on canonical payloads)? Is it still?"

No — this was fixed by retraining, and the fix is verified, not assumed. Here's
the full arc:

1. **Diagnosis**: a quick manual sanity check (bare payload strings, no
   wrapper) showed the *original* shipped model correctly classifying
   `<script>...</script>` and `cmd=ls;cat /etc/passwd` as vulnerable. But once
   the *same* payloads were embedded into realistic request shapes (e.g.
   `https://example.com/search?q=<payload>`), the model's prediction flipped
   to SAFE almost every time. Conclusion: the model had learned surface shape,
   not attack content.
2. **Fix**: `benchmark/build_training_corpus.py` builds a new fine-tuning
   corpus with two hard rules: (a) every malicious payload is a *different*
   literal string from anything in the evaluation corpus (mechanically
   verified — see the "zero overlap" check at the bottom of that script), so
   any improvement is generalization, not memorization; (b) benign samples use
   the *same* request templates as malicious ones, so the model can't
   shortcut on wrapper shape. The corpus also includes every payload bare,
   percent-encoded, and case/whitespace-mangled.
3. **Retraining**: `webguard/train_web_model.py benchmark/training_corpus.csv
   --output_dir webguard/web_vuln_model_v2 --epochs 5 --batch_size 16`. Ran
   on an RTX 5050 Laptop GPU, ~3-4 minutes for 5 epochs.
4. **Re-verification**: re-ran the *identical, unmodified* benchmark. Overall
   CodeBERT-alone recall went from 0.036 to **0.970**, precision unchanged at
   1.000 (zero new false positives). Because the training and evaluation
   payload catalogs are provably disjoint, this is a real measurement of
   generalization to unseen attack strings.
5. **Deployment**: the old model was renamed to `web_vuln_model_v1_archived`
   (kept for comparison — don't delete it) and the new one renamed to
   `web_vuln_model`, so `backend.py` picks it up with zero code changes.

**If asked "how do you know this isn't just as overfit as before, to a
different shape?"** — because the improvement was measured on payload
strings the model never saw during training (mechanically verified zero
overlap), and because we then went further (see next section) and
specifically tried to break it with a harder, adversarial stress test rather
than stopping at the flattering aggregate number.

## "Is the 0.970 recall the whole story? Did you just stop there?"

> **Update (November 2026):** both cases below are now partly handled by the
> revised rules — a value that *ends* in a quote (`id=1'`) is flagged, and
> redirect targets are compared with the request's own host when the input
> includes one. The reasoning below still holds for inputs where that
> information is missing. See the November 2026 section at the top.

No — and this is probably the single most important thing to understand
about this paper if you're defending it. A 0.970 number is exactly the kind
of result you should distrust until you've tried to break it. We did, with
`benchmark/stress_test_ood.py`, using strings in neither the training nor
evaluation corpus. Two things survived every attempt to fix them:

**1. Bare-quote SQLi (`'`, `1'`, no keyword).** All 10 of the retrained
model's remaining misses on the full 672-sample benchmark are this exact
case. The pattern engine fails on it too (`b.detect_patterns("...q='")`
returns `[]` — check it yourself). This is not a training-data gap: a lone
apostrophe is genuinely ambiguous in plain English (`O'Brien`, `it's`), so no
amount of lexical pattern-matching or text classification can resolve it
from the string alone. **This is literally the exact case from the very
first screenshot in this whole project** (`id=1'` against the vulnerable
demo server) — full circle. The only way to resolve it is to look at what
the server actually does, which is what the response-body evidence sensor
and `active_scan.py`'s `check_sql_error()` already do.

**2. Open-redirect origin comparison.** The retrained model hit 100% recall
on the benchmark's own redirect samples — but that number is inflated by a
coincidence: the benchmark's redirect payload (`webguard-evil.example`, from
`active_scan.py`) happens to share a reserved TLD family (`.test`/`.example`)
with most of the training domains. Tested against domains outside that
family (`evil.com`, `sketchysite.org`), the model was wrong 3 times out of
4 — *even after two full rounds of adding dozens more diverse training
domains across multiple TLDs*. We also found the exact same root cause on
the pattern-engine side: its regex hardcodes an exception for
`.example`/`.test`/`.localhost` domains (to avoid flagging this codebase's
own placeholders), which means it will *also* incorrectly flag a genuine
same-origin redirect on a real domain, because it has no way to know what
the real origin is. Both failures are the same problem: **telling same-origin
from cross-origin apart requires comparing two things (the page's real origin
and the redirect target) — information that does not exist in a single input
string, no matter how it's classified.** `test_open_redirect_url()` in
`active_scan.py` sidesteps this entirely by not guessing: it sends its own
unambiguous external marker domain and directly observes the server's real
`Location` header.

**Why we stopped trying to fix these two specific cases**: continuing to add
training data or regex tweaks aimed at making `evil.com` or a bare `'` pass
would have meant overfitting to my own test probes rather than solving the
actual, structural problem. The correct fix already exists in a different
layer of the system (active scanning), and the paper says so explicitly.
If a reviewer asks "why didn't you just add more data until it worked?" —
answer: because the problem isn't a data quantity problem, it's an
information-availability problem, and no dataset size fixes that.

## "Walk me through the percent-encoding bug and fix."

1. **Bug**: `detect_patterns()` in `backend.py` (before the fix) ran its
   regexes against the raw input string only. A regex like
   `r"'\s*(or|and)\s+['\"0-9]"` expects a literal apostrophe. If the
   apostrophe arrives as `%27` (its percent-encoded form), the literal
   character is never present in the string the regex sees, so it can't
   match — even though a URL decoder would reveal the exact same attack.
2. **Measurement**: `benchmark/results_before_fix.json` (this snapshot
   predates BOTH the decoding fix and the CodeBERT retraining — it's the
   very first run, against the original shipped model). `by_variant.
   percent_encoded.pattern.recall` is 0.125 there vs. 0.643 for the
   canonical variant. `benchmark/results.json` (current) reflects the fully
   fixed and retrained system; `results_after_retraining.json` is an
   identical snapshot of that final state, kept as a named artifact.
3. **Fix**: `backend.py`'s `detect_patterns()` now also computes
   `urllib.parse.unquote(code)` and checks patterns against both the raw
   and decoded text (set union — decoding can only add matches, never
   remove a match that fired before). Minimal, targeted, one function.
4. **Re-verification**: re-ran the exact same benchmark after the fix.
   Percent-encoded recall recovered to 0.643 (identical to canonical),
   precision stayed at 1.000 (zero new false positives on the 336-sample
   benign set), and canonical/mangled results were unchanged (confirms no
   regression). This before/after pair is Table IV in the paper.

## "Why is precision 1.000 in every single configuration? Isn't that suspicious?"

It means zero false positives on this specific 336-sample benign set — worth
being skeptical of, which is exactly why the paper caveats it explicitly
("we caution that this reflects zero false positives on our specific,
comparatively small benign corpus and should not be read as a general
false-positive-rate guarantee"). If pressed: the benign corpus is real URLs/
HTTP requests with no attack syntax in them (view a few rows of
`datasets/safe_samples.csv` yourself), so it is plausible that none of them
accidentally contain a SQL/XSS/path-traversal pattern — but a larger,
more adversarial benign set (e.g., URLs that legitimately contain special
characters) is exactly the kind of follow-up test that could break this
number, and the paper says so.

## "What hardware were the latency numbers measured on, and is that disclosed?"

Yes — Table V states it plainly: AMD64 CPU, NVIDIA GeForce RTX 5050 Laptop
GPU, CUDA available (the CodeBERT pipeline loads on GPU when available,
matching `backend.py`'s own `device=0 if torch.cuda.is_available() else -1`
logic). Verify with `torch.cuda.get_device_name(0)` yourself if asked. The
paper does not claim these numbers generalize to other machines — that's
in Limitations.

## "What is the Related Work sourced from, and how sure are you it's accurate?"

Each recent citation (`uniembed`, `sqirl`, `evade-obfuscate`) was located via
web search and its author list/venue/year verified against a second,
independent source before being added to the bibliography (see chat history
for the verification searches). The paper itself flags this: "the recent
related work cited above was identified and summarized from its published
abstract and metadata; readers relying on this positioning for further work
should consult the primary sources directly." **Before you submit, you
personally should skim each paper's abstract at minimum** — if asked a
detailed question about SQIRL's reinforcement-learning reward function, for
instance, and you haven't read past the abstract, say so rather than
bluffing.

## "Walk me through the whole CodeBERT story end to end, in order."

This is likely the single question you'll get asked most, since it spans
most of the paper. The honest, complete arc, in the order it actually
happened:

1. Original shipped model: 0.036 overall recall, 0.009 on canonical
   payloads — fragile, keys on request-shape not content.
2. Diagnosed via manual spot-checks: bare payloads correctly classified,
   wrapped payloads flipped to SAFE.
3. Built a new training corpus (`build_training_corpus.py`) — disjoint
   payloads from eval, matched benign/malicious templates, bare + encoded +
   mangled coverage.
4. Retrained (`train_web_model.py`) → recall recovered to 0.970, verified
   on the untouched benchmark with provably zero payload overlap.
5. First retrain attempt had 2 regressions (bare XSS, redirect to a novel
   domain) — caught by spot-checking against the *original* motivating
   examples, not just trusting the aggregate number. Fixed by adding a bare
   (unwrapped) template and diversifying redirect training domains.
6. Deployed the fixed retrain as production (`web_vuln_model`), archived
   the original as `web_vuln_model_v1_archived`.
7. Stress-tested harder with genuinely novel domains/strings
   (`stress_test_ood.py`) specifically to try to break the good number.
8. Found two residual failures (bare-quote SQLi, redirect to `evil.com`-
   style domains) that survived further diversification attempts.
9. Diagnosed the common root cause: both need information a single string
   cannot contain (real server behavior; true page origin) — not a data
   quantity problem.
10. Confirmed WebGuard's active-scanning layer already solves both
    correctly by a different mechanism (behavioral observation, not text
    classification) — concluded that this validates the architecture rather
    than needing yet another patch.

If you can retell this arc in your own words with the numbers at each step,
you can defend this paper.

---

## Things you must still personally verify before submission

- [ ] Real author names/affiliations in place of "Given Name Surname"
- [ ] Confirm Cyber-AI 2026's page limit (8 pages incl. references — verified
      via web search, but re-check the actual CFP page yourself) and whether
      review is double-blind (not confirmed either way — if blind, anonymize
      the author block and any self-identifying text before submitting)
- [ ] Compile on Overleaf and check actual page count fits the limit —
      several tables/sections were added and this was never compiled locally
- [ ] Skim the abstracts of the 3 new citations yourself
- [ ] Re-run `benchmark/run_benchmark.py` yourself at least once so you've
      personally seen the numbers come out, not just read this file
- [ ] Re-run `benchmark/stress_test_ood.py` yourself and look at the raw
      output — it's short and this is the finding most likely to get
      follow-up questions
- [ ] If you want to reproduce the retraining from scratch: `python
      benchmark/build_training_corpus.py` then `python
      webguard/train_web_model.py benchmark/training_corpus.csv
      --output_dir webguard/web_vuln_model_v2 --epochs 5 --batch_size 16`
      (takes a few minutes on a GPU; `web_vuln_model_v1_archived/` holds the
      original for comparison, do not delete it)
