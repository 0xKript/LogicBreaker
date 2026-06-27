#!/usr/bin/env python3
"""
LogicBreaker AI -- accuracy benchmark
====================================

Measures the scanner's precision and recall against a *labelled* corpus:

  benchmark/cases/vulnerable/  -- files that DO contain a known vulnerability
                                  (each should produce at least one finding)
  benchmark/cases/safe/        -- files that look similar but are SAFE
                                  (each should produce ZERO findings)

Metrics reported:
  * True Positives (TP)  -- vulnerable files correctly flagged
  * False Negatives (FN) -- vulnerable files missed
  * False Positives (FP) -- safe files wrongly flagged
  * True Negatives (TN)  -- safe files correctly left clean
  * Precision = TP / (TP + FP)   -> of what we flagged, how much was real
  * Recall    = TP / (TP + FN)   -> of the real vulns, how many we caught
  * False-Positive Rate = FP / (FP + TN)

This is a file-level benchmark (does the scanner correctly decide whether a
file is vulnerable?). It is intentionally honest: the safe set is full of
look-alikes (parameterized queries, locked critical sections, UI text that
says "Select", regex patterns, comments that mention vulns) precisely to
expose over-eager matching.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scan_engine import ScanEngine


def scan_file_dir(path):
    eng = ScanEngine(path)
    result = eng.scan()
    # group findings by file
    by_file = {}
    for f in result["findings"]:
        by_file.setdefault(os.path.basename(f.file), []).append(f)
    return by_file


def run():
    here = os.path.dirname(os.path.abspath(__file__))
    vuln_dir = os.path.join(here, "cases", "vulnerable")
    safe_dir = os.path.join(here, "cases", "safe")

    vuln_findings = scan_file_dir(vuln_dir)
    safe_findings = scan_file_dir(safe_dir)

    vuln_files = [f for f in os.listdir(vuln_dir) if not f.startswith(".")]
    safe_files = [f for f in os.listdir(safe_dir) if not f.startswith(".")]

    tp = [f for f in vuln_files if vuln_findings.get(f)]
    fn = [f for f in vuln_files if not vuln_findings.get(f)]
    fp = [f for f in safe_files if safe_findings.get(f)]
    tn = [f for f in safe_files if not safe_findings.get(f)]

    TP, FN, FP, TN = len(tp), len(fn), len(fp), len(tn)
    precision = TP / (TP + FP) if (TP + FP) else 0.0
    recall = TP / (TP + FN) if (TP + FN) else 0.0
    fpr = FP / (FP + TN) if (FP + TN) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    print("=" * 64)
    print("  LogicBreaker AI — Accuracy Benchmark")
    print("=" * 64)
    print(f"  Vulnerable files: {len(vuln_files)}   Safe files: {len(safe_files)}")
    print("-" * 64)
    print(f"  True Positives  (caught real vulns):     {TP}/{len(vuln_files)}")
    print(f"  False Negatives (missed real vulns):     {FN}/{len(vuln_files)}")
    print(f"  False Positives (flagged safe code):     {FP}/{len(safe_files)}")
    print(f"  True Negatives  (safe code left clean):  {TN}/{len(safe_files)}")
    print("-" * 64)
    print(f"  Precision           : {precision*100:5.1f}%   (of flagged, how much was real)")
    print(f"  Recall              : {recall*100:5.1f}%   (of real vulns, how many caught)")
    print(f"  False-Positive Rate : {fpr*100:5.1f}%   (healthy range ~5-15%)")
    print(f"  F1 score            : {f1*100:5.1f}%")
    print("=" * 64)

    if fn:
        print("\n  MISSED (false negatives) — should have been flagged:")
        for f in fn:
            print(f"    - {f}")
    if fp:
        print("\n  FALSE ALARMS (false positives) — safe code wrongly flagged:")
        for f in fp:
            types = ", ".join(sorted({x.type for x in safe_findings[f]}))
            print(f"    - {f}  ->  {types}")
    if not fn and not fp:
        print("\n  Perfect on this corpus: every vuln caught, no false alarms.")
    print()
    return {"precision": precision, "recall": recall, "fpr": fpr, "f1": f1,
            "TP": TP, "FN": FN, "FP": FP, "TN": TN}


if __name__ == "__main__":
    run()
