# stress_test_ood.py
#
# Out-of-distribution stress test for the retrained web_vuln_model, run
# AFTER the full benchmark (run_benchmark.py) showed a near-perfect 0.970
# overall recall. A single strong aggregate number is exactly the kind of
# result that should be stress-tested harder before being trusted, so this
# script deliberately probes two things the main benchmark cannot rule out:
#
# 1. Open Redirect generalization to domains OUTSIDE the reserved TLD family
#    (.test/.example/.invalid) used throughout training. The eval corpus's
#    own redirect payload (webguard-evil.example, from active_scan.py)
#    happens to share that TLD family with training data -- zero exact
#    payload-string overlap (verified in build_training_corpus.py), but a
#    shared superficial trait that could inflate the eval number without
#    reflecting true domain-agnostic generalization.
#
# 2. Bare single-quote SQLi ("'" / "1'") with no accompanying SQL keyword --
#    the exact case from this project's original motivating example
#    (id=1' on the demo vulnerable server). A lone apostrophe is genuinely
#    ambiguous in plain text (it appears in benign strings like "O'Brien"),
#    so this tests whether that ambiguity is inherent to the signal itself,
#    not an artifact of training data.
#
# Both use domains/strings that never appeared in training or in the
# eval corpus, so this is a genuine held-out probe, not a re-run of
# anything already measured.

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webguard"))
import backend as b  # noqa: E402

REDIRECT_PROBES = [
    ("real-style TLD, short",   "https://example.com/redirect?url=https://evil.com"),
    ("real-style TLD, .org",    "https://example.com/redirect?url=http://sketchysite.org"),
    ("real-style TLD, .com, no scheme", "https://example.com/next?url=fake-bank-login.com"),
    ("real-style TLD, .net",    "https://example.com/login?next=https://randomsite123.net/x"),
    ("benign internal path",    "https://example.com/redirect?url=/dashboard"),
    ("benign same-domain",      "https://example.com/redirect?url=https://example.com/home"),
]

SQLI_PROBES = [
    ("bare quote, no keyword",     "https://example.com/search?q='"),
    ("bare quote + digit",         "https://example.com/search?q=1'"),
    ("quote WITH keyword (control)", "https://example.com/search?q=' OR 1=1--"),
    ("benign apostrophe in text",  "https://example.com/search?q=O'Brien"),
]


def run(label, probes):
    detector = b.get_vulnerability_detector()
    print(f"\n=== {label} ===")
    for name, text in probes:
        pattern_hit = bool(b.detect_patterns(text))
        ml_result = detector(text[:512])[0]
        ml_hit = ml_result["label"] in ("INSECURE", "LABEL_1", "1", "VULNERABLE")
        print(f"  {name:34s} pattern={'HIT ' if pattern_hit else 'miss'}  "
              f"ml={'HIT ' if ml_hit else 'miss'} ({ml_result['score']:.3f})  | {text[:50]}")


if __name__ == "__main__":
    run("Open Redirect: out-of-training-TLD-family domains", REDIRECT_PROBES)
    run("SQL Injection: bare-quote ambiguity", SQLI_PROBES)
