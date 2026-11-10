# build_dataset.py
#
# Builds a transparent, reproducible evaluation set for the WebGuard paper.
#
# WHY THIS EXISTS: the original vulnerable-sample half of the CSV used to
# train web_vuln_model is no longer present in the repository (datasets/
# only contains safe_samples.csv, which is 100% label=0). We cannot
# reconstruct the original train/val/test split. Rather than report
# unverifiable numbers, this script builds a NEW, fully-documented
# evaluation set from material that already exists in the codebase:
#
#   - BENIGN samples  <- datasets/safe_samples.csv (deduplicated), which is
#                        part of the same benign corpus the model trained on.
#   - MALICIOUS samples <- WebGuard's OWN attack payload catalog
#                        (webguard/active_scan.py's real SQLi/XSS/path/cmd/
#                        redirect payloads, used verbatim in the guided active
#                        scanner) plus hand-authored canonical examples for
#                        the categories active_scan.py doesn't test
#                        (SSRF, XXE, SSTI, hardcoded credentials), each
#                        matched to the exact regex in backend.py's
#                        WEB_PATTERNS so ground truth is unambiguous.
#
# Each payload is embedded into several realistic request shapes (query
# string, raw HTTP request block) to avoid the classes being trivially
# separable by surface format alone. Two evasion transforms are then
# generated per payload (percent-encoding, and case/whitespace mangling) to
# test whether detection survives simple obfuscation.
#
# Every sample keeps its provenance (category, cwe, obfuscation type) so
# the benchmark can break results down by subgroup instead of reporting one
# opaque number.

import csv
import json
import random
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webguard"))
import active_scan as a  # noqa: E402  (WebGuard's real payload catalog)

random.seed(42)
ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = Path(__file__).resolve().parent

# ── Hand-authored canonical payloads for categories active_scan.py does
# not actively test, each crafted to trip the exact regex in
# webguard/backend.py's WEB_PATTERNS (kept in sync manually; see paper
# Table II / Methodology for the mapping this mirrors). ──
EXTRA_PAYLOADS = {
    "SSRF": [
        ("http://169.254.169.254/latest/meta-data/", "cwe-918_meta"),
        ("http://127.0.0.1:6379/", "cwe-918_loopback"),
        ("file:///etc/passwd", "cwe-918_file_scheme"),
        ("gopher://internal:70/_x", "cwe-918_gopher"),
    ],
    "XXE": [
        ('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', "cwe-611_entity"),
    ],
    "SSTI": [
        ("{{7*7}}", "cwe-94_jinja"),
        ("{% print(7*7) %}", "cwe-94_block"),
    ],
    "Hardcoded Credentials": [
        ('password="Sup3rSecretPassw0rd!"', "cwe-798_password"),
        ('api_key="AKIA1234567890ABCDEF"', "cwe-798_apikey"),
    ],
}

# category -> CWE, mirrors backend.py WEB_PATTERNS / paper Table II
CWE = {
    "SQL Injection": "CWE-89", "XSS": "CWE-79", "Path Traversal": "CWE-22",
    "Command Injection": "CWE-78", "Open Redirect": "CWE-601",
    "SSRF": "CWE-918", "XXE": "CWE-611", "SSTI": "CWE-94",
    "Hardcoded Credentials": "CWE-798",
}

# request-shape templates the payload is embedded into (keeps malicious and
# benign samples structurally similar, so classifiers can't cheat on format)
TEMPLATES = [
    lambda p: f"https://example.com/search?q={p}",
    lambda p: f"https://shop.example.com/item?id={p}&ref=home",
    lambda p: f"GET /profile?user={p} HTTP/1.1\nHost: app.example.com\n",
    lambda p: f"POST /api/submit HTTP/1.1\nHost: service.example.com\nContent-Type: application/x-www-form-urlencoded\n\ndata={p}",
]


def case_mangle(payload):
    """Deterministic case-randomization + whitespace/comment padding —
    a simple, common evasion technique against case-sensitive or
    whitespace-sensitive signatures."""
    out = []
    for i, ch in enumerate(payload):
        out.append(ch.upper() if (i % 2 == 0 and ch.isalpha()) else ch)
    mangled = "".join(out)
    mangled = mangled.replace(" ", "  /**/ ")
    return mangled


def percent_encode(payload):
    """Single percent-encoding of the payload's special characters — the
    same style of evasion the CFP/OWASP testing guide flags as a common
    WAF/signature bypass."""
    return urllib.parse.quote(payload, safe="")


def build_malicious():
    rows = []  # (text, label=1, category, cwe, variant, base_payload)

    catalog = {
        "SQL Injection":     [p for p, _ in a.SQL_PAYLOADS] + [p for p, _ in a.SQL_PAYLOADS_SLOW],
        "XSS":               [p for p, _ in a.XSS_PAYLOADS],
        "Path Traversal":    [p for p, _ in a.PATH_PAYLOADS],
        "Command Injection": [p for p, _ in a.CMD_PAYLOADS],
        "Open Redirect":     [p for p, _ in a.REDIRECT_PAYLOADS],
    }
    for cat, extra in EXTRA_PAYLOADS.items():
        catalog[cat] = [p for p, _ in extra]

    for cat, payloads in catalog.items():
        cwe = CWE[cat]
        for payload in payloads:
            for tmpl in TEMPLATES:
                base_text = tmpl(payload)
                rows.append({"text": base_text, "label": 1, "category": cat,
                             "cwe": cwe, "variant": "canonical", "base_payload": payload})

                enc_text = tmpl(percent_encode(payload))
                rows.append({"text": enc_text, "label": 1, "category": cat,
                             "cwe": cwe, "variant": "percent_encoded", "base_payload": payload})

                mangled_text = tmpl(case_mangle(payload))
                rows.append({"text": mangled_text, "label": 1, "category": cat,
                             "cwe": cwe, "variant": "case_whitespace_mangled", "base_payload": payload})
    return rows


def build_benign(n):
    import pandas as pd
    df = pd.read_csv(ROOT / "datasets" / "safe_samples.csv", low_memory=False)
    df = df.drop_duplicates(subset=["text"])
    df = df[df["label"] == 0]
    sample = df.sample(n=min(n, len(df)), random_state=42)
    return [{"text": t, "label": 0, "category": "benign", "cwe": "-",
              "variant": "canonical", "base_payload": ""} for t in sample["text"].tolist()]


def main():
    malicious = build_malicious()
    benign = build_benign(len(malicious))
    all_rows = malicious + benign
    random.shuffle(all_rows)

    out_csv = OUT_DIR / "eval_set.csv"
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["text", "label", "category", "cwe", "variant", "base_payload"])
        w.writeheader()
        w.writerows(all_rows)

    summary = {
        "total": len(all_rows),
        "malicious": len(malicious),
        "benign": len(benign),
        "by_category": {},
        "by_variant": {},
    }
    for r in malicious:
        summary["by_category"][r["category"]] = summary["by_category"].get(r["category"], 0) + 1
        summary["by_variant"][r["variant"]] = summary["by_variant"].get(r["variant"], 0) + 1

    with open(OUT_DIR / "eval_set_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"Wrote {out_csv} ({len(all_rows)} rows: {len(malicious)} malicious, {len(benign)} benign)")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
