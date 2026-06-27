#!/usr/bin/env python3
"""
LogicBreaker AI -- Test Runner (10x)
====================================

Runs the AI detector + investigator over the bundled test corpus 10 times and
reports detection rate per case + overall.

The corpus is split into:
  test_corpus/vulnerable/        -- 23 Python files, each MUST be flagged
  test_corpus/wordpress_vuln/    -- 10 PHP files, each MUST be flagged
  test_corpus/safe/              -- 12 Python files, each MUST NOT be flagged
  test_corpus/wordpress_safe/    -- 6 PHP files, each MUST NOT be flagged

A run is "100% accurate" only if:
  * every vulnerable file produced >= 1 confirmed finding, AND
  * every safe file produced 0 confirmed findings.

The script uses the LLM client (set LB_TEST_PROVIDER and LB_TEST_API_KEY env
vars, or run without them to use the deterministic engine only).
"""

import json
import os
import sys
import time
import traceback
from pathlib import Path

# add project root to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agents.ai_detector import AIDetector
from core.case_validator import Investigator

TEST_DIR = ROOT / "test_corpus"
VULN_DIRS = [TEST_DIR / "vulnerable", TEST_DIR / "wordpress_vuln"]
SAFE_DIRS = [TEST_DIR / "safe", TEST_DIR / "wordpress_safe"]


def collect_cases():
    """Return (vuln_files, safe_files) -- lists of (path, language, expected_vuln)."""
    vuln = []
    safe = []
    ext_lang = {".py": "python", ".php": "php", ".js": "javascript",
                ".ts": "typescript", ".java": "java", ".go": "go",
                ".rb": "ruby", ".cs": "c_sharp"}
    for d in VULN_DIRS:
        for p in sorted(d.glob("*")):
            if p.suffix in ext_lang:
                vuln.append((p, ext_lang[p.suffix]))
    for d in SAFE_DIRS:
        for p in sorted(d.glob("*")):
            if p.suffix in ext_lang:
                safe.append((p, ext_lang[p.suffix]))
    return vuln, safe


def make_llm():
    """Build an LLM client from env vars, or return None for engine-only mode."""
    provider = os.environ.get("LB_TEST_PROVIDER", "")
    api_key = os.environ.get("LB_TEST_API_KEY", "")
    if not provider or not api_key:
        return None
    from agents.llm_client import LLMClient
    return LLMClient(provider=provider, api_key=api_key)


def scan_one_file(llm, path: Path, language: str, diag: dict = None):
    """Run the AI detector + investigator on a single file. Returns the list of
    accepted verdicts (may be empty)."""
    code = path.read_text(encoding="utf-8", errors="replace")
    if llm is not None and getattr(llm, "available", False):
        detector = AIDetector(llm)
        try:
            cases = detector.detect(code, language=language, file_path=str(path))
        except Exception as e:
            if diag is not None:
                diag.append(f"{path.name}: detect error: {type(e).__name__}: {e}")
            return []
        inv = Investigator(language)
        verdicts = inv.validate_all(cases, code)
        return [v for v in verdicts if v.accepted]
    else:
        # engine-only mode -- use the deterministic matchers
        from core.scan_engine import ScanEngine
        # ScanEngine expects a directory; we make a temp dir with one file
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            import shutil
            dst = os.path.join(td, path.name)
            shutil.copy(path, dst)
            results = ScanEngine(td).scan()
            return results.get("findings", [])


def run_one_iteration(llm, iteration: int, vuln_files, safe_files):
    """Run one full pass over the corpus. Returns a dict of results."""
    results = {
        "iteration": iteration,
        "vuln_detected": 0,
        "vuln_missed": 0,
        "vuln_details": [],
        "safe_correctly_clean": 0,
        "safe_false_positives": 0,
        "safe_details": [],
        "errors": [],
    }

    for path, lang in vuln_files:
        verdicts = scan_one_file(llm, path, lang, results["errors"])
        if verdicts:
            results["vuln_detected"] += 1
            results["vuln_details"].append({
                "file": path.name,
                "found": True,
                "count": len(verdicts),
                "types": [getattr(v, "case", None) and v.case.name or
                          getattr(v, "type", "?") for v in verdicts][:3],
            })
        else:
            results["vuln_missed"] += 1
            results["vuln_details"].append({
                "file": path.name,
                "found": False,
                "count": 0,
                "types": [],
            })

    for path, lang in safe_files:
        verdicts = scan_one_file(llm, path, lang, results["errors"])
        if not verdicts:
            results["safe_correctly_clean"] += 1
            results["safe_details"].append({
                "file": path.name, "found": False, "count": 0, "types": [],
            })
        else:
            results["safe_false_positives"] += 1
            results["safe_details"].append({
                "file": path.name,
                "found": True,
                "count": len(verdicts),
                "types": [getattr(v, "case", None) and v.case.name or
                          getattr(v, "type", "?") for v in verdicts][:3],
            })

    return results


def print_iteration_result(r: dict, total_vuln: int, total_safe: int):
    print(f"\n{'='*70}")
    print(f"  Iteration {r['iteration']}")
    print(f"{'='*70}")
    print(f"  Vulnerable files:  detected {r['vuln_detected']}/{total_vuln}, "
          f"missed {r['vuln_missed']}")
    print(f"  Safe files:        clean {r['safe_correctly_clean']}/{total_safe}, "
          f"false positives {r['safe_false_positives']}")
    if r["vuln_missed"]:
        print(f"\n  MISSED vulnerable files:")
        for d in r["vuln_details"]:
            if not d["found"]:
                print(f"    - {d['file']}")
    if r["safe_false_positives"]:
        print(f"\n  FALSE POSITIVES on safe files:")
        for d in r["safe_details"]:
            if d["found"]:
                print(f"    - {d['file']} (got: {d['types']})")
    if r["errors"]:
        print(f"\n  Errors ({len(r['errors'])}):")
        for e in r["errors"][:5]:
            print(f"    - {e}")


def main():
    n_iterations = int(os.environ.get("LB_TEST_ITERATIONS", "10"))
    vuln_files, safe_files = collect_cases()
    print(f"\nLogicBreaker AI -- {n_iterations}x Test Runner")
    print(f"  Corpus: {len(vuln_files)} vulnerable + {len(safe_files)} safe files")

    llm = make_llm()
    if llm is None:
        print("  Mode: ENGINE-ONLY (no LLM key set)")
        print("  Set LB_TEST_PROVIDER and LB_TEST_API_KEY to test the AI layer.")
    else:
        ok, msg = llm.validate_key()
        if not ok:
            print(f"  LLM key validation failed: {msg}")
            print("  Falling back to ENGINE-ONLY mode.")
            llm = None
        else:
            print(f"  Mode: AI-assisted ({llm.provider} / {llm.model})")

    all_results = []
    perfect_runs = 0
    for i in range(1, n_iterations + 1):
        t0 = time.time()
        r = run_one_iteration(llm, i, vuln_files, safe_files)
        r["elapsed_sec"] = round(time.time() - t0, 2)
        all_results.append(r)
        print_iteration_result(r, len(vuln_files), len(safe_files))
        print(f"  Elapsed: {r['elapsed_sec']}s")
        is_perfect = (r["vuln_missed"] == 0 and r["safe_false_positives"] == 0)
        if is_perfect:
            perfect_runs += 1
            print(f"  >>> PERFECT RUN")

    print(f"\n{'='*70}")
    print(f"  FINAL SUMMARY ({n_iterations} iterations)")
    print(f"{'='*70}")
    print(f"  Perfect runs:    {perfect_runs}/{n_iterations}")
    # per-file detection rate across all iterations
    from collections import defaultdict
    file_detections = defaultdict(int)
    file_false_pos = defaultdict(int)
    for r in all_results:
        for d in r["vuln_details"]:
            if d["found"]:
                file_detections[d["file"]] += 1
        for d in r["safe_details"]:
            if d["found"]:
                file_false_pos[d["file"]] += 1

    print(f"\n  Per-vulnerable-file detection rate:")
    for path, _ in vuln_files:
        rate = file_detections.get(path.name, 0) / n_iterations * 100
        marker = " OK " if rate == 100 else "FAIL"
        print(f"    [{marker}] {path.name:50s} {rate:5.1f}%")

    print(f"\n  Per-safe-file false-positive rate:")
    for path, _ in safe_files:
        rate = file_false_pos.get(path.name, 0) / n_iterations * 100
        marker = " OK " if rate == 0 else "FAIL"
        print(f"    [{marker}] {path.name:50s} {rate:5.1f}%")

    overall_detection = sum(r["vuln_detected"] for r in all_results) / \
                        (n_iterations * len(vuln_files)) * 100
    overall_fp = sum(r["safe_false_positives"] for r in all_results) / \
                 (n_iterations * len(safe_files)) * 100
    print(f"\n  Overall detection rate:   {overall_detection:5.1f}%")
    print(f"  Overall false-positive rate: {overall_fp:5.1f}%")
    print(f"  Perfect runs: {perfect_runs}/{n_iterations}")

    # save the detailed results
    out_path = ROOT / "test_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({
            "n_iterations": n_iterations,
            "n_vuln": len(vuln_files),
            "n_safe": len(safe_files),
            "perfect_runs": perfect_runs,
            "overall_detection_pct": overall_detection,
            "overall_fp_pct": overall_fp,
            "iterations": all_results,
            "per_file": {
                "vuln": {k: v for k, v in file_detections.items()},
                "safe_fp": {k: v for k, v in file_false_pos.items()},
            },
        }, f, indent=2, default=str)
    print(f"\n  Detailed results saved to: {out_path}")

    # exit non-zero if not perfect
    sys.exit(0 if perfect_runs == n_iterations else 1)


if __name__ == "__main__":
    main()
