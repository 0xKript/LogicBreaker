#!/usr/bin/env python3
"""
Mock LLM test -- verifies the AI detector + investigator + anti-hallucination
pipeline works correctly with a MOCKED LLM that returns pre-scripted findings.

This proves the  anti-hallucination architecture (consensus + self-critique +
strict investigator) is sound, WITHOUT needing a real LLM API key. We feed the
detector a series of mocked LLM responses and verify:
  1. Genuine vulnerabilities (correct snippet/sink) are ACCEPTED.
  2. Hallucinated vulnerabilities (wrong snippet) are REJECTED.
  3. The consensus flag works (findings in both passes get consensus=True).
  4. The self-critique retracts findings the model itself cannot defend.
"""

import os
import sys
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agents.ai_detector import AIDetector, CaseFile, build_detection_prompt, number_code


class MockLLM:
    """A fake LLM that returns pre-scripted JSON replies, one per call.

    We use this to verify the detector's parsing, consensus, and self-critique
    logic without needing a real API key. Each call to chat_json pops the next
    reply from the queue (cycling if exhausted).
    """

    def __init__(self, replies):
        self.replies = list(replies)
        self.call_count = 0
        self.available = True

    def chat_json(self, system, user, **kwargs):
        if not self.replies:
            return {"findings": []}
        idx = self.call_count % len(self.replies)
        self.call_count += 1
        reply = self.replies[idx]
        if isinstance(reply, str):
            import json as _json
            return _json.loads(reply)
        return reply

    def chat(self, system, user, **kwargs):
        # not used by the detector, but provide for completeness
        return json.dumps(self.chat_json(system, user, **kwargs))


def test_genuine_md5_is_accepted():
    """A correct MD5 finding (verbatim snippet) must be ACCEPTED by the
    investigator."""
    code = "import hashlib\ndef hash_password(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n"
    # the detector will make 3 calls: pass1, pass2 (consensus), critique
    genuine = {
        "findings": [{
            "name": "Weak Cryptography",
            "cwe": "CWE-327",
            "severity": "HIGH",
            "confidence": 95,
            "snippet": "return hashlib.md5(pw.encode()).hexdigest()",
            "source": "N/A",
            "sink": "hashlib.md5",
            "data_flow": [],
            "why": "MD5 is collision-prone and fast.",
            "impact": "Passwords can be brute-forced.",
            "fix": "Use bcrypt or argon2.",
            "sanitizer_check": "N/A",
            "exploit": {"type": "function", "payload": "hashcat", "expected": "pw recovered"}
        }]
    }
    critique = {"verdicts": [{"keep": True}]}
    mock = MockLLM([genuine, genuine, critique])
    det = AIDetector(mock, enable_consensus=True, enable_critique=True, n_passes=2)
    cases = det.detect(code, language="python", file_path="test.py")
    assert len(cases) == 1, f"expected 1 case, got {len(cases)}"
    assert cases[0].cwe == "CWE-327"
    assert cases[0].consensus, "consensus flag should be True (in both passes)"
    assert cases[0].self_critique_ok, "self-critique should have kept it"
    # now verify the investigator accepts it
    from core.case_validator import Investigator
    inv = Investigator("python")
    verdicts = inv.validate_all(cases, code)
    assert len(verdicts) == 1
    assert verdicts[0].accepted, f"investigator should accept genuine MD5: {verdicts[0].reason}"
    print("[PASS] test_genuine_md5_is_accepted")


def test_hallucinated_snippet_is_rejected_by_investigator():
    """A finding with an invented snippet (not in the file) must be REJECTED by
    the investigator. This is the core anti-hallucination guarantee."""
    code = "import hashlib\ndef hash_password(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n"
    hallucinated = {
        "findings": [{
            "name": "SQL Injection",
            "cwe": "CWE-89",
            "severity": "CRITICAL",
            "confidence": 90,
            "snippet": "db.execute('SELECT * FROM users WHERE id=' + user_input)",  # NOT in file
            "source": "request.args['id']",
            "sink": "db.execute",
            "data_flow": ["user_input"],
            "why": "User input concatenated into SQL.",
            "impact": "DB compromise.",
            "fix": "Parameterize.",
            "sanitizer_check": "none",
            "exploit": {"type": "http", "payload": "id=1 OR 1=1", "expected": "all rows"}
        }]
    }
    critique = {"verdicts": [{"keep": True}]}  # even if critique keeps it, investigator must reject
    mock = MockLLM([hallucinated, hallucinated, critique])
    det = AIDetector(mock, enable_consensus=True, enable_critique=True, n_passes=2)
    cases = det.detect(code, language="python", file_path="test.py")
    # the detector produces the case, but the investigator must REJECT it
    from core.case_validator import Investigator
    inv = Investigator("python")
    verdicts = inv.validate_all(cases, code)
    assert len(verdicts) == 1
    assert not verdicts[0].accepted, "investigator must reject hallucinated snippet"
    assert "snippet does not appear" in verdicts[0].reason, \
        f"reason should mention snippet: {verdicts[0].reason}"
    print("[PASS] test_hallucinated_snippet_is_rejected_by_investigator")


def test_self_critique_retracts_findings():
    """When the self-critique pass retracts a finding, it must NOT appear in the
    detector's output."""
    code = "import hashlib\ndef hash_password(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n"
    genuine = {
        "findings": [{
            "name": "Weak Cryptography",
            "cwe": "CWE-327",
            "severity": "HIGH",
            "confidence": 95,
            "snippet": "return hashlib.md5(pw.encode()).hexdigest()",
            "source": "N/A",
            "sink": "hashlib.md5",
            "data_flow": [],
            "why": "MD5 is weak.",
            "impact": "Brute-forceable.",
            "fix": "Use bcrypt.",
            "sanitizer_check": "N/A",
            "exploit": {"type": "none", "payload": "", "expected": ""}
        }]
    }
    # critique retracts the finding
    critique = {"verdicts": [{"keep": False, "reason": "snippet not verbatim"}]}
    mock = MockLLM([genuine, genuine, critique])
    det = AIDetector(mock, enable_consensus=True, enable_critique=True, n_passes=2)
    cases = det.detect(code, language="python", file_path="test.py")
    assert len(cases) == 0, "self-critique should have retracted the only finding"
    print("[PASS] test_self_critique_retracts_findings")


def test_consensus_flag_distinguishes_passes():
    """A finding present in both passes gets consensus=True; one in only one
    pass gets consensus=False."""
    code = "import hashlib\ndef hash_password(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n"
    md5 = {
        "findings": [{
            "name": "Weak Cryptography", "cwe": "CWE-327", "severity": "HIGH",
            "confidence": 90, "snippet": "return hashlib.md5(pw.encode()).hexdigest()",
            "source": "N/A", "sink": "hashlib.md5", "data_flow": [],
            "why": "MD5 weak.", "impact": "brute-force.", "fix": "bcrypt.",
            "sanitizer_check": "N/A",
            "exploit": {"type": "none", "payload": "", "expected": ""}
        }]
    }
    des = {
        "findings": [{
            "name": "Weak Cryptography", "cwe": "CWE-327", "severity": "HIGH",
            "confidence": 90, "snippet": "return hashlib.md5(pw.encode()).hexdigest()",
            "source": "N/A", "sink": "hashlib.md5", "data_flow": [],
            "why": "MD5 weak.", "impact": "brute-force.", "fix": "bcrypt.",
            "sanitizer_check": "N/A",
            "exploit": {"type": "none", "payload": "", "expected": ""}
        }]
    }
    # pass1 returns md5 only; pass2 returns md5 + des (both same fingerprint -> deduped)
    # so only md5 survives, with consensus=True
    critique = {"verdicts": [{"keep": True}]}
    mock = MockLLM([md5, md5, critique])
    det = AIDetector(mock, enable_consensus=True, enable_critique=True, n_passes=2)
    cases = det.detect(code, language="python", file_path="test.py")
    assert len(cases) == 1
    assert cases[0].consensus, "md5 was in both passes -> consensus=True"
    print("[PASS] test_consensus_flag_distinguishes_passes")


def test_investigator_strict_anchor_rejects_partial_snippet():
    """ hardening: a tiny snippet like 'md5(' must NOT anchor to any line
    containing 'md5' -- it must be a substantial match."""
    code = "import hashlib\ndef f():\n    x = hashlib.md5(b'hello')\n    return x\n"
    from core.case_validator import Investigator
    inv = Investigator("python")
    # case with a trivial snippet
    case = CaseFile(
        name="Weak Crypto", cwe="CWE-327", severity="HIGH", confidence=90,
        snippet="md5(",  # tiny -- must NOT anchor
        source="N/A", sink="hashlib.md5", data_flow=[],
        why="weak", sanitizer_check="N/A",
        exploit={"type": "none", "payload": "", "expected": ""})
    verdict = inv.validate(case, code)
    assert not verdict.accepted, "trivial snippet 'md5(' must be rejected by strict anchor"
    print("[PASS] test_investigator_strict_anchor_rejects_partial_snippet")


def test_investigator_function_scoped_source_check():
    """ hardening: a claimed source that is NOT in the same function as the
    sink must be REJECTED (the old check accepted any source in the file)."""
    # the source is in func_a, the sink is in func_b -- they are NOT on the
    # same flow
    code = (
        "from flask import Flask, request\n"
        "import os\n"
        "app = Flask(__name__)\n"
        "def func_a():\n"
        "    user = request.args.get('x')  # source here\n"
        "    return user\n"
        "\n"
        "@app.route('/r')\n"
        "def func_b():\n"
        "    os.system('echo hello')  # sink here -- NOT connected to source\n"
        "    return 'ok'\n"
    )
    from core.case_validator import Investigator
    inv = Investigator("python")
    case = CaseFile(
        name="OS Command Injection", cwe="CWE-78", severity="CRITICAL", confidence=85,
        snippet="os.system('echo hello')",
        source="request.args.get('x')",  # this is in func_a, not func_b
        sink="os.system", data_flow=["user"],
        why="tainted", sanitizer_check="none",
        exploit={"type": "http", "payload": "x; rm -rf /", "expected": "rce"})
    verdict = inv.validate(case, code)
    # the source is real and in the file, but NOT in the same function as sink
    #  this must be rejected
    assert not verdict.accepted, \
        f"function-scoped source check should reject cross-function claim: {verdict.reason}"
    print("[PASS] test_investigator_function_scoped_source_check")


def test_property_vuln_no_source_required():
    """Property vulns (MD5, hardcoded, debug) should be accepted with anchor +
    sink only, no source check needed.

     the investigator takes the family from the AI's claim. We set
    family='property' explicitly so the source check is skipped."""
    code = "import hashlib\ndef hash_password(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n"
    from core.case_validator import Investigator
    inv = Investigator("python")
    case = CaseFile(
        name="Weak Cryptography", cwe="CWE-327", severity="HIGH", confidence=95,
        snippet="return hashlib.md5(pw.encode()).hexdigest()",
        source="N/A", sink="hashlib.md5", data_flow=[],
        why="MD5 is weak", sanitizer_check="N/A",
        exploit={"type": "none", "payload": "", "expected": ""})
    case.family = "property"  #  AI's family claim
    verdict = inv.validate(case, code)
    assert verdict.accepted, f"property vuln should be accepted: {verdict.reason}"
    assert verdict.family == "property"
    print("[PASS] test_property_vuln_no_source_required")


def main():
    print("\n" + "="*70)
    print("  LogicBreaker AI -- Mock LLM Anti-Hallucination Tests")
    print("="*70 + "\n")
    tests = [
        test_genuine_md5_is_accepted,
        test_hallucinated_snippet_is_rejected_by_investigator,
        test_self_critique_retracts_findings,
        test_consensus_flag_distinguishes_passes,
        test_investigator_strict_anchor_rejects_partial_snippet,
        test_investigator_function_scoped_source_check,
        test_property_vuln_no_source_required,
    ]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {t.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {t.__name__}: {type(e).__name__}: {e}")
            failed += 1
    print(f"\n{'='*70}")
    print(f"  Results: {passed} passed, {failed} failed")
    print(f"{'='*70}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
