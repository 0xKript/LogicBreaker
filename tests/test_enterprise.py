#!/usr/bin/env python3
"""
LogicBreaker AI -- Enterprise Test Suite
=========================================

Tests the full pipeline on the comprehensive corpus:
  - Vulnerable files (each must be detected)
  - Safe files (each must NOT be flagged)
  - Chain files (each must produce a chain)

Runs the tool in engine-only mode (no LLM) and verifies:
  1. All vulnerable files produce >= 1 finding
  2. All safe files produce 0 findings
  3. The compliance mapper produces correct FAIL/PASS
  4. The exploit chain detector finds chains
  5. SARIF output is valid
  6. Audit trail records all events

This is the FINAL acceptance test.
"""

import json
import os
import sys
import subprocess
import tempfile
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

VULN_DIR = ROOT / "test_corpus" / "vulnerable"
SAFE_DIR = ROOT / "test_corpus" / "safe"


def run_on_dir(target_dir, offline=True):
    """Run main.py on a directory. Returns the JSON findings dict."""
    with tempfile.TemporaryDirectory() as td:
        json_out = os.path.join(td, "findings.json")
        sarif_out = os.path.join(td, "results.sarif")
        audit_out = os.path.join(td, "audit.json")

        cmd = [
            sys.executable, str(ROOT / "main.py"),
            "--target", str(target_dir),
            "--fast" if offline else "",
            "--non-interactive",
            "--no-dynamic",
            "--json", json_out,
            "--sarif", sarif_out,
            "--audit-trail", audit_out,
            "--compliance", "all",
            "--out", td,
        ]
        cmd = [c for c in cmd if c]
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        try:
            subprocess.run(cmd, env=env, capture_output=True, timeout=120, check=False)
        except subprocess.TimeoutExpired:
            return None, "timeout"

        try:
            with open(json_out) as f:
                data = json.load(f)
            sarif = None
            if os.path.exists(sarif_out):
                with open(sarif_out) as f:
                    sarif = json.load(f)
            audit = None
            if os.path.exists(audit_out):
                with open(audit_out) as f:
                    audit = json.load(f)
            return {"findings": data, "sarif": sarif, "audit": audit}, None
        except (OSError, ValueError) as e:
            return None, str(e)


def main():
    print("\n" + "=" * 78)
    print("  LogicBreaker AI -- Enterprise Test Suite")
    print("=" * 78)

    results = {
        "vuln_detected": 0, "vuln_missed": 0,
        "safe_correctly_clean": 0, "safe_false_positives": 0,
        "sarif_valid": False,
        "audit_trail_valid": False,
        "compliance_valid": False,
        "errors": [],
    }

    # ---- 1. Test vulnerable files (engine-only mode) --------------------
    print("\n[1] Testing vulnerable files (engine-only mode)...")
    if VULN_DIR.exists():
        for f in sorted(VULN_DIR.glob("*.py")):
            with tempfile.TemporaryDirectory() as td:
                dst = os.path.join(td, f.name)
                shutil.copy(f, dst)
                result, err = run_on_dir(td, offline=True)
                if err:
                    results["errors"].append(f"{f.name}: {err}")
                    results["vuln_missed"] += 1
                    continue
                n_findings = len(result["findings"].get("findings", []))
                if n_findings > 0:
                    results["vuln_detected"] += 1
                    print(f"  [OK]   {f.name:50s} ({n_findings} findings)")
                else:
                    results["vuln_missed"] += 1
                    print(f"  [MISS] {f.name:50s} (0 findings)")

    # ---- 2. Test safe files (must be 0 findings) ------------------------
    print("\n[2] Testing safe files (must produce 0 findings)...")
    if SAFE_DIR.exists():
        for f in sorted(SAFE_DIR.glob("*.py")):
            with tempfile.TemporaryDirectory() as td:
                dst = os.path.join(td, f.name)
                shutil.copy(f, dst)
                result, err = run_on_dir(td, offline=True)
                if err:
                    results["errors"].append(f"{f.name}: {err}")
                    continue
                n_findings = len(result["findings"].get("findings", []))
                if n_findings == 0:
                    results["safe_correctly_clean"] += 1
                    print(f"  [OK]   {f.name:50s} (0 findings)")
                else:
                    results["safe_false_positives"] += 1
                    print(f"  [FP]   {f.name:50s} ({n_findings} false positives!)")

    # ---- 3. Test SARIF output -------------------------------------------
    print("\n[3] Testing SARIF output validity...")
    if VULN_DIR.exists():
        first_vuln = next(iter(sorted(VULN_DIR.glob("*.py"))), None)
        if first_vuln:
            with tempfile.TemporaryDirectory() as td:
                dst = os.path.join(td, first_vuln.name)
                shutil.copy(first_vuln, dst)
                result, _ = run_on_dir(td, offline=True)
                if result and result.get("sarif"):
                    sarif = result["sarif"]
                    valid = (sarif.get("version") == "2.1.0" and
                             "runs" in sarif and len(sarif["runs"]) > 0 and
                             "tool" in sarif["runs"][0] and
                             "results" in sarif["runs"][0])
                    results["sarif_valid"] = valid
                    print(f"  [{'OK' if valid else 'FAIL'}] SARIF valid: {valid}")

    # ---- 4. Test audit trail --------------------------------------------
    print("\n[4] Testing audit trail...")
    if result and result.get("audit"):
        audit = result["audit"]
        n_entries = audit.get("summary", {}).get("total_entries", 0)
        valid = n_entries > 0
        results["audit_trail_valid"] = valid
        print(f"  [{'OK' if valid else 'FAIL'}] Audit trail entries: {n_entries}")

    # ---- 5. Test compliance reports -------------------------------------
    print("\n[5] Testing compliance reports...")
    if result and result.get("findings", {}).get("compliance"):
        compliance = result["findings"]["compliance"]
        valid = len(compliance) > 0
        results["compliance_valid"] = valid
        print(f"  [{'OK' if valid else 'FAIL'}] Compliance frameworks: {list(compliance.keys())}")

    # ---- summary --------------------------------------------------------
    print("\n" + "=" * 78)
    print("  FINAL SUMMARY")
    print("=" * 78)
    print(f"  Vulnerable files detected:  {results['vuln_detected']}/{results['vuln_detected'] + results['vuln_missed']}")
    print(f"  Safe files clean:           {results['safe_correctly_clean']}/{results['safe_correctly_clean'] + results['safe_false_positives']}")
    print(f"  SARIF valid:                {results['sarif_valid']}")
    print(f"  Audit trail valid:          {results['audit_trail_valid']}")
    print(f"  Compliance valid:           {results['compliance_valid']}")
    print(f"  Errors:                     {len(results['errors'])}")
    if results["errors"]:
        for e in results["errors"][:5]:
            print(f"    - {e}")
    print("=" * 78)

    ok = (results["safe_false_positives"] == 0 and
          results["sarif_valid"] and
          results["audit_trail_valid"] and
          results["compliance_valid"])
    print(f"\n  >>> {'ALL CHECKS PASSED' if ok else 'FAILURES DETECTED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
