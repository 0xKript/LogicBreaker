#!/usr/bin/env python3
"""
LogicBreaker AI -- enhanced self-validating accuracy benchmark (v2)
===================================================================

Same labelled corpus as run_benchmark.py:
  benchmark/cases/vulnerable/  -- each file MUST produce >= 1 finding
  benchmark/cases/safe/        -- each file MUST produce 0 findings

What v2 adds on top of the simple pass/fail gate:
  * a metadata manifest (cases.json) describing every case
    (id / title / cwe / severity / language / context / difficulty / why),
  * per-CWE, per-language, per-severity and per-DIFFICULTY accuracy breakdowns,
  * a prominent list of any FAILING case (the exact file + what it did wrong),
    so the corpus can be grown safely (each new case is validated, not assumed).

Difficulty tiers (declared in the manifest):
  obvious      -- a direct, high-confidence pattern
  hidden       -- a non-obvious / interprocedural / lightly-obfuscated pattern
  adversarial  -- a trap (safe code that looks dangerous) or a multi-step flow

This is detection-only (it never runs the fixer), so changes to the auto-patch
engine cannot affect the score.
"""

import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scan_engine import ScanEngine

HERE = os.path.dirname(os.path.abspath(__file__))
VULN_DIR = os.path.join(HERE, "cases", "vulnerable")
SAFE_DIR = os.path.join(HERE, "cases", "safe")
MANIFEST = os.path.join(HERE, "cases.json")


def scan_dir(path):
    by_file = defaultdict(list)
    for f in ScanEngine(path).scan()["findings"]:
        by_file[os.path.basename(f.file)].append(f)
    return by_file


def load_manifest():
    if not os.path.exists(MANIFEST):
        return {}
    with open(MANIFEST, encoding="utf-8") as fh:
        data = json.load(fh)
    # manifest is a list of case dicts keyed by "file"
    return {c["file"]: c for c in data if "file" in c}


def pct(n, d):
    return (100.0 * n / d) if d else 0.0


def bar(p, width=22):
    filled = int(round(p / 100 * width))
    return "█" * filled + "·" * (width - filled)


def main():
    meta = load_manifest()
    vuln_files = sorted(f for f in os.listdir(VULN_DIR) if not f.startswith("."))
    safe_files = sorted(f for f in os.listdir(SAFE_DIR) if not f.startswith("."))

    vuln_hits = scan_dir(VULN_DIR)
    safe_hits = scan_dir(SAFE_DIR)

    tp = [f for f in vuln_files if vuln_hits.get(f)]
    fn = [f for f in vuln_files if not vuln_hits.get(f)]
    fp = [f for f in safe_files if safe_hits.get(f)]
    tn = [f for f in safe_files if not safe_hits.get(f)]

    total = len(vuln_files) + len(safe_files)
    precision = pct(len(tp), len(tp) + len(fp))
    recall = pct(len(tp), len(tp) + len(fn))
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = pct(len(fp), len(fp) + len(tn))

    print("=" * 64)
    print("  LogicBreaker AI -- Enhanced Accuracy Benchmark (v2)")
    print("=" * 64)
    print(f"  Total cases            : {total}   ({len(vuln_files)} vulnerable + {len(safe_files)} safe)")
    print(f"  True Positives         : {len(tp)}/{len(vuln_files)}")
    print(f"  False Negatives        : {len(fn)}/{len(vuln_files)}")
    print(f"  False Positives        : {len(fp)}/{len(safe_files)}")
    print(f"  True Negatives         : {len(tn)}/{len(safe_files)}")
    print("  " + "-" * 60)
    print(f"  Precision              : {precision:5.1f}%   {bar(precision)}")
    print(f"  Recall                 : {recall:5.1f}%   {bar(recall)}")
    print(f"  F1 score               : {f1:5.1f}%   {bar(f1)}")
    print(f"  False-Positive Rate    : {fpr:5.1f}%")
    print()

    # ---- breakdowns from the manifest -------------------------------------
    def correct(fname, is_vuln):
        return bool(vuln_hits.get(fname)) if is_vuln else not bool(safe_hits.get(fname))

    def breakdown(key):
        agg = defaultdict(lambda: [0, 0])  # value -> [correct, total]
        for fname in vuln_files:
            c = meta.get(fname, {})
            v = c.get(key, "?")
            agg[v][1] += 1
            agg[v][0] += correct(fname, True)
        for fname in safe_files:
            c = meta.get(fname, {})
            v = c.get(key, "?")
            agg[v][1] += 1
            agg[v][0] += correct(fname, False)
        return agg

    if meta:
        for title, key in [("BY CWE", "cwe"), ("BY LANGUAGE", "language"),
                           ("BY DIFFICULTY", "difficulty"), ("BY SEVERITY", "severity")]:
            agg = breakdown(key)
            print(f"  {title}")
            for v in sorted(agg, key=lambda k: (-agg[k][1], str(k))):
                c, t = agg[v]
                print(f"    {str(v)[:34]:34} {c:>3}/{t:<3}  {pct(c, t):5.1f}%  {bar(pct(c, t), 14)}")
            print()
    else:
        print("  (no cases.json manifest found -- per-category breakdown skipped)")
        print()

    # ---- failures, loudly -------------------------------------------------
    ok = not fn and not fp
    if fn:
        print("  ✗ MISSED (false negatives) -- vulnerable files NOT flagged:")
        for f in fn:
            print(f"      - {f}")
    if fp:
        print("  ✗ FALSE ALARMS (false positives) -- safe files wrongly flagged:")
        for f in fp:
            kinds = ", ".join(sorted({x.type for x in safe_hits[f]}))
            print(f"      - {f}  ->  {kinds}")
    if ok:
        print("  ✓ PERFECT on this corpus: every vulnerability caught, zero false alarms.")
    print("=" * 64)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
