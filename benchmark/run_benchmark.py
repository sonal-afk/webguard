# run_benchmark.py
#
# Benchmarks the REAL WebGuard detection pipeline (imported directly from
# webguard/backend.py — not reimplemented) against benchmark/eval_set.csv
# (see build_dataset.py for how that set was constructed and why).
#
# Three arms, all using the actual production functions:
#   pattern  -> detect_patterns()                        (backend.py)
#   ml       -> the CodeBERT pipeline, forced (bypasses pattern early-exit)
#   hybrid   -> analyze()                                 (backend.py, real
#                production decision logic: pattern first, ML fallback)
#
# Reports precision/recall/F1/accuracy overall AND broken down by evasion
# variant (canonical / percent_encoded / case_whitespace_mangled), plus
# mean per-item latency for each arm on this machine. All numbers are
# printed and saved to benchmark/results.json for direct citation in the
# paper — nothing here is hand-typed into the manuscript.

import csv
import json
import sys
import time
import platform
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webguard"))
import backend as b  # noqa: E402  (the real Flask backend module)

OUT_DIR = Path(__file__).resolve().parent


def load_eval_set():
    rows = []
    with open(OUT_DIR / "eval_set.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            r["label"] = int(r["label"])
            rows.append(r)
    return rows


def pattern_only_predict(text):
    # detect_patterns() already drops categories the input visibly mitigates
    # (same rule analyze() uses), so any remaining finding means "vulnerable".
    return 1 if b.detect_patterns(text) else 0


def ml_only_predict(detector, text):
    try:
        result = detector(text[:512])[0]
        label = result["label"]
        return 1 if label in ("INSECURE", "LABEL_1", "1", "VULNERABLE") else 0
    except Exception:
        return 0


def hybrid_predict(text):
    # "Flagged" = confirmed by a rule (vulnerable) OR raised by the model for
    # review (needs_review). This is everything the system draws attention to.
    result = b.analyze(text)
    return 1 if (result["vulnerable"] or result.get("needs_review")) else 0


def confusion(y_true, y_pred):
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    acc       = (tp + tn) / len(y_true) if y_true else 0.0
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn,
             "precision": round(precision, 4), "recall": round(recall, 4),
             "f1": round(f1, 4), "accuracy": round(acc, 4), "n": len(y_true)}


def measure_latency(fn, texts, reps=1):
    # warm-up (excludes one-off JIT/lazy-load cost from the timed average)
    fn(texts[0])
    t0 = time.perf_counter()
    for _ in range(reps):
        for t in texts:
            fn(t)
    elapsed = time.perf_counter() - t0
    return (elapsed / (reps * len(texts))) * 1000  # ms/item


def main():
    rows = load_eval_set()
    texts = [r["text"] for r in rows]
    labels = [r["label"] for r in rows]

    print(f"Loaded {len(rows)} eval rows.")
    print("Loading ML model...")
    detector = b.get_vulnerability_detector()
    if detector is None:
        print("FATAL: model failed to load:", b.model_load_error)
        sys.exit(1)

    print("Running pattern-only predictions...")
    pattern_preds = [pattern_only_predict(t) for t in texts]

    print("Running ML-only predictions (bypassing pattern early-exit)...")
    ml_preds = [ml_only_predict(detector, t) for t in texts]

    print("Running hybrid (real analyze()) predictions...")
    hybrid_preds = [hybrid_predict(t) for t in texts]

    # ── Overall metrics per arm ──
    results = {
        "hardware": {
            "platform": platform.platform(),
            "processor": platform.processor(),
        },
        "dataset": {"n": len(rows)},
        "overall": {
            "pattern": confusion(labels, pattern_preds),
            "ml":      confusion(labels, ml_preds),
            "hybrid":  confusion(labels, hybrid_preds),
        },
        "by_variant": {},
        "latency_ms": {},
    }

    # ── Breakdown by evasion variant (malicious rows only; benign has no variant) ──
    variants = sorted(set(r["variant"] for r in rows if r["label"] == 1))
    for variant in variants:
        idx = [i for i, r in enumerate(rows) if r["variant"] == variant or r["label"] == 0]
        y_true = [labels[i] for i in idx]
        results["by_variant"][variant] = {
            "pattern": confusion(y_true, [pattern_preds[i] for i in idx]),
            "ml":      confusion(y_true, [ml_preds[i] for i in idx]),
            "hybrid":  confusion(y_true, [hybrid_preds[i] for i in idx]),
        }

    # ── Latency (ms/item), measured on this machine ──
    sample_texts = texts[:100]  # latency probe subset, avoids re-running all 672 many times
    results["latency_ms"]["pattern"] = round(measure_latency(pattern_only_predict, sample_texts), 4)
    results["latency_ms"]["ml"]      = round(measure_latency(lambda t: ml_only_predict(detector, t), sample_texts), 4)
    results["latency_ms"]["hybrid"]  = round(measure_latency(hybrid_predict, sample_texts), 4)

    with open(OUT_DIR / "results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 60)
    print("OVERALL (n=%d)" % len(rows))
    print("=" * 60)
    for arm in ["pattern", "ml", "hybrid"]:
        m = results["overall"][arm]
        print(f"{arm:8s}  P={m['precision']:.3f}  R={m['recall']:.3f}  F1={m['f1']:.3f}  "
              f"Acc={m['accuracy']:.3f}  (TP={m['tp']} TN={m['tn']} FP={m['fp']} FN={m['fn']})")

    print("\n" + "=" * 60)
    print("BY EVASION VARIANT")
    print("=" * 60)
    for variant in variants:
        print(f"\n-- {variant} --")
        for arm in ["pattern", "ml", "hybrid"]:
            m = results["by_variant"][variant][arm]
            print(f"  {arm:8s}  P={m['precision']:.3f}  R={m['recall']:.3f}  F1={m['f1']:.3f}  Acc={m['accuracy']:.3f}")

    print("\n" + "=" * 60)
    print("LATENCY (ms/item, this machine: %s)" % results["hardware"]["processor"])
    print("=" * 60)
    for arm in ["pattern", "ml", "hybrid"]:
        print(f"  {arm:8s}  {results['latency_ms'][arm]:.3f} ms")

    print(f"\nSaved full results to {OUT_DIR / 'results.json'}")


if __name__ == "__main__":
    main()
