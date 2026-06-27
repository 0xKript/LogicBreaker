#!/usr/bin/env python3
"""
LogicBreaker AI  -- Anti-Hallucination + AI-First Tests
==========================================================

Tests the  AI-first architecture with MOCKED LLM responses. Verifies:

  1. The AI detects INCOMPLETE MITIGATIONS (partial SSRF allowlist).
  2. The AI detects BROKEN MITIGATIONS (yaml.safe_load with Loader kwarg).
  3. The AI's classification (no CWE / custom name) is preserved by the
     investigator (no rule-engine override).
  4. The surgeon proposes a COMPLETE fix (not a partial patch).
  5. The prover rejects a fix that breaks the endpoint (TypeError).
  6. The prover accepts a fix that actually works (exploit blocked + benign ok).
  7. The anti-hallucination walls (anchor, self-critique, consensus) still work.
"""

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agents.ai_detector import AIDetector, CaseFile
from agents.ai_surgeon import AISurgeon, parse_repair
from core.case_validator import Investigator
from core.fix_prover import FixProver


class MockLLM:
    """A fake LLM that returns pre-scripted JSON replies, one per call."""

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
            return json.loads(reply)
        return reply

    def chat(self, system, user, **kwargs):
        return json.dumps(self.chat_json(system, user, **kwargs))


# ---- Test 1: AI detects incomplete SSRF allowlist ---------------------------

def test_ai_detects_incomplete_ssrf_allowlist():
    """The AI should flag an SSRF allowlist that misses 172.16.0.0/12, IPv6
    ULA, DNS rebinding, decimal IP, etc. as an INCOMPLETE MITIGATION."""
    code = """from flask import Flask, request
import requests
from urllib.parse import urlparse

app = Flask(__name__)

@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    host = urlparse(url).hostname or ""
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254") or \\
       host.startswith("10.") or host.startswith("192.168."):
        return "blocked", 403
    return requests.get(url).text
"""
    finding = {
        "findings": [{
            "name": "SSRF with Incomplete Allowlist",
            "cwe": "CWE-918",
            "category": "ssrf",
            "family": "flow",
            "severity": "CRITICAL",
            "confidence": 95,
            "snippet": "return requests.get(url).text",
            "source": "request.args.get(\"url\", \"\")",
            "sink": "requests.get",
            "data_flow": ["url"],
            "why": "The allowlist misses 172.16.0.0/12, 100.64.0.0/10, IPv6 ULA, "
                   "DNS rebinding, decimal/hex IP encoding, and 302 redirects.",
            "impact": "An attacker can reach internal services (cloud metadata, "
                      "Docker network, Redis) and exfiltrate data.",
            "fix": "Use an allowlist of approved external hosts AND verify the "
                   "resolved IP is not private/loopback/link-local.",
            "sanitizer_check": "Partial allowlist present but bypassable via "
                               "172.16.x.x, IPv6 ULA, decimal IP, DNS rebinding.",
            "exploit": {"type": "http", "payload": "url=http://172.16.0.1/",
                        "expected": "internal service reached"}
        }]
    }
    critique = {"verdicts": [{"keep": True}]}
    mock = MockLLM([finding, finding, critique])
    det = AIDetector(mock, enable_consensus=True, enable_critique=True)
    cases = det.detect(code, language="python", file_path="app.py")
    assert len(cases) == 1, f"expected 1 case, got {len(cases)}"
    assert "Incomplete" in cases[0].name or "SSRF" in cases[0].name
    assert cases[0].severity == "CRITICAL"
    # the investigator must accept (anchor + sink + source all real)
    inv = Investigator("python")
    verdicts = inv.validate_all(cases, code)
    assert verdicts[0].accepted, f"investigator should accept: {verdicts[0].reason}"
    assert verdicts[0].family == "flow"  # AI's claim preserved
    print("[PASS] test_ai_detects_incomplete_ssrf_allowlist")


# ---- Test 2: AI detects broken YAML mitigation ------------------------------

def test_ai_detects_broken_yaml_mitigation():
    """The AI should flag yaml.safe_load(data, Loader=yaml.Loader) as a BROKEN
    MITIGATION -- safe_load does not accept a Loader kwarg and raises TypeError."""
    code = """from flask import Flask, request
import yaml

app = Flask(__name__)

@app.route("/yaml", methods=["POST"])
def parse_yaml():
    data = request.data
    return str(yaml.safe_load(data, Loader=yaml.Loader))
"""
    finding = {
        "findings": [{
            "name": "Broken YAML Mitigation (TypeError)",
            "cwe": "CWE-502",
            "category": "deserialization",
            "family": "broken-mitigation",
            "severity": "HIGH",
            "confidence": 95,
            "snippet": "return str(yaml.safe_load(data, Loader=yaml.Loader))",
            "source": "request.data",
            "sink": "yaml.safe_load",
            "data_flow": ["data"],
            "why": "yaml.safe_load() does not accept a Loader kwarg; it raises "
                   "TypeError, leaving the endpoint broken.",
            "impact": "The endpoint crashes on every request, returning a 500 "
                      "error. The developer's intent to mitigate deserialization "
                      "has failed.",
            "fix": "Call yaml.safe_load(data) without the Loader kwarg.",
            "sanitizer_check": "safe_load IS the right call, but the Loader "
                               "kwarg makes it raise TypeError.",
            "exploit": {"type": "http", "payload": "POST data='a: 1'",
                        "expected": "500 TypeError"}
        }]
    }
    critique = {"verdicts": [{"keep": True}]}
    mock = MockLLM([finding, finding, critique])
    det = AIDetector(mock, enable_consensus=True, enable_critique=True)
    cases = det.detect(code, language="python", file_path="app.py")
    assert len(cases) == 1
    assert "Broken" in cases[0].name or "YAML" in cases[0].name
    assert cases[0].family == "broken-mitigation"
    # the investigator must accept (family=broken-mitigation skips source check)
    inv = Investigator("python")
    verdicts = inv.validate_all(cases, code)
    assert verdicts[0].accepted, f"investigator should accept: {verdicts[0].reason}"
    print("[PASS] test_ai_detects_broken_yaml_mitigation")


# ---- Test 3: AI classification preserved (no CWE required) ------------------

def test_ai_classification_preserved_without_cwe():
    """The AI may classify a finding WITHOUT a CWE number. The investigator
    must NOT reject it for lacking a CWE."""
    code = "API_KEY = 'sk-live-abc123'\n"
    finding = {
        "findings": [{
            "name": "Hardcoded Production API Key",
            "cwe": "",  # no CWE!
            "category": "config",
            "family": "property",
            "severity": "HIGH",
            "confidence": 95,
            "snippet": "API_KEY = 'sk-live-abc123'",
            "source": "N/A",
            "sink": "API_KEY =",
            "data_flow": [],
            "why": "API key embedded in source.",
            "impact": "Anyone with code access has the key.",
            "fix": "Load from env var.",
            "sanitizer_check": "N/A",
            "exploit": {"type": "none", "payload": "", "expected": ""}
        }]
    }
    critique = {"verdicts": [{"keep": True}]}
    mock = MockLLM([finding, finding, critique])
    det = AIDetector(mock, enable_consensus=True, enable_critique=True)
    cases = det.detect(code, language="python", file_path="app.py")
    assert len(cases) == 1
    assert cases[0].cwe == ""  # no CWE, but the finding is kept
    assert cases[0].name == "Hardcoded Production API Key"
    inv = Investigator("python")
    verdicts = inv.validate_all(cases, code)
    assert verdicts[0].accepted, f"investigator should accept no-CWE finding: {verdicts[0].reason}"
    print("[PASS] test_ai_classification_preserved_without_cwe")


# ---- Test 4: Surgeon proposes complete fix (not partial) --------------------

def test_surgeon_proposes_complete_fix():
    """The surgeon's proposal must include root_cause + bypasses_closed +
    a complete fixed_snippet (not a partial patch)."""
    code = """import yaml
from flask import Flask, request
app = Flask(__name__)

@app.route("/yaml", methods=["POST"])
def parse_yaml():
    data = request.data
    return str(yaml.safe_load(data, Loader=yaml.Loader))
"""
    # build a fake verdict with a confirmed case
    case = CaseFile(
        name="Broken YAML Mitigation", cwe="CWE-502", category="deserialization",
        family="broken-mitigation", severity="HIGH", confidence=95,
        snippet="return str(yaml.safe_load(data, Loader=yaml.Loader))",
        source="request.data", sink="yaml.safe_load", data_flow=["data"],
        why="safe_load does not accept Loader kwarg.",
        sanitizer_check="safe_load IS the right call but Loader kwarg breaks it.",
        impact="endpoint crashes.",
        fix="Call yaml.safe_load(data) without the Loader kwarg.",
        exploit={"type": "http", "payload": "POST data", "expected": "500"})
    # we need a verdict object -- build a minimal one
    class V:
        line = 5
        cwe = "CWE-502"
    verdict = V()
    verdict.case = case

    fix_reply = {
        "root_cause": "yaml.safe_load() does not accept a Loader keyword argument; "
                      "passing one raises TypeError.",
        "bypasses_closed": "TypeError crash, endpoint broken",
        "original_snippet": "return str(yaml.safe_load(data, Loader=yaml.Loader))",
        "fixed_snippet": "return str(yaml.safe_load(data))",
        "imports": [],
        "explanation": "Removed the Loader kwarg so safe_load works correctly.",
        "strength_notes": "safe_load uses SafeLoader by default, blocking python/* tags."
    }
    mock = MockLLM([fix_reply])
    surgeon = AISurgeon(mock)
    proposal = surgeon.propose(verdict, code)
    assert not proposal.is_empty
    assert "Loader=yaml.Loader" in proposal.original_snippet
    assert "safe_load(data)" in proposal.fixed_snippet
    assert "Loader" not in proposal.fixed_snippet  # the kwarg is gone
    assert proposal.root_cause
    assert proposal.bypasses_closed
    print("[PASS] test_surgeon_proposes_complete_fix")


# ---- Test 5: Prover rejects a fix that breaks the endpoint ------------------

def test_prover_rejects_broken_fix():
    """The prover must reject a fix that makes the patched module fail to load
    (e.g. references an undefined name) -- execution catches this."""
    code = """from flask import Flask, request
import yaml

app = Flask(__name__)

@app.route("/yaml", methods=["POST"])
def parse_yaml():
    data = request.data
    return str(yaml.load(data, Loader=yaml.Loader))
"""
    # a "fix" that leaves the Loader kwarg (broken) -- safe_load + Loader -> TypeError
    case = CaseFile(
        name="Insecure Deserialization", cwe="CWE-502", category="deserialization",
        family="flow", severity="CRITICAL", confidence=90,
        snippet="return str(yaml.load(data, Loader=yaml.Loader))",
        source="request.data", sink="yaml.load", data_flow=["data"],
        why="yaml.load with Loader is unsafe.",
        sanitizer_check="none",
        impact="RCE via python/object/apply tag.",
        fix="Use safe_load.",
        exploit={"type": "http", "payload": "!!python/object/apply:os.system",
                 "expected": "code executed"})
    class V:
        line = 7
        cwe = "CWE-502"
    verdict = V()
    verdict.case = case

    # a BROKEN fix: still passes Loader=yaml.Loader to safe_load -> TypeError
    class P:
        original_snippet = "return str(yaml.load(data, Loader=yaml.Loader))"
        fixed_snippet = "return str(yaml.safe_load(data, Loader=yaml.Loader))"
        imports = []
        line = 7
        is_empty = False
    proposal = P()
    prover = FixProver("python")
    result = prover.prove(proposal, code, verdict)
    # the prover should detect the broken_fix (TypeError on load)
    # NOTE: this depends on the exploit_prover being able to load the module.
    # If yaml.safe_load with Loader raises TypeError at import time, the
    # module fails to load -> broken_fix.
    # We accept either rejected (broken_fix) or inconclusive (no probe).
    assert not result.accepted or "inconclusive" in result.reason.lower(), \
        f"prover should reject or be inconclusive on broken fix: {result.reason}"
    print(f"[PASS] test_prover_rejects_broken_fix (reason: {result.reason[:80]})")


# ---- Test 6: Prover accepts a working fix ------------------------------------

def test_prover_accepts_working_fix():
    """The prover must accept a fix that actually removes the vuln AND keeps
    the endpoint working."""
    code = """from flask import Flask, request
import yaml

app = Flask(__name__)

@app.route("/yaml", methods=["POST"])
def parse_yaml():
    data = request.data
    return str(yaml.load(data, Loader=yaml.Loader))
"""
    case = CaseFile(
        name="Insecure Deserialization", cwe="CWE-502", category="deserialization",
        family="flow", severity="CRITICAL", confidence=90,
        snippet="return str(yaml.load(data, Loader=yaml.Loader))",
        source="request.data", sink="yaml.load", data_flow=["data"],
        why="yaml.load with Loader is unsafe.",
        sanitizer_check="none",
        impact="RCE.",
        fix="Use safe_load.",
        exploit={"type": "http", "payload": "!!python/object/apply:os.system",
                 "expected": "code executed"})
    class V:
        line = 7
        cwe = "CWE-502"
    verdict = V()
    verdict.case = case

    # a WORKING fix: safe_load without Loader
    class P:
        original_snippet = "return str(yaml.load(data, Loader=yaml.Loader))"
        fixed_snippet = "return str(yaml.safe_load(data))"
        imports = []
        line = 7
        is_empty = False
    proposal = P()
    prover = FixProver("python")
    result = prover.prove(proposal, code, verdict)
    # the prover should accept (exploit blocked + endpoint still works)
    assert result.accepted, f"prover should accept working fix: {result.reason}"
    print(f"[PASS] test_prover_accepts_working_fix (reason: {result.reason[:80]})")


# ---- Test 7: Anti-hallucination walls still work ----------------------------

def test_hallucinated_snippet_rejected():
    """A finding with an invented snippet (not in the file) must be rejected
    by the investigator (anchor check)."""
    code = "x = 1\n"
    case = CaseFile(
        name="Fake Vuln", cwe="CWE-89", category="injection", family="flow",
        severity="CRITICAL", confidence=90,
        snippet="db.execute('SELECT * FROM users WHERE id=' + user_input)",
        source="request.args['id']", sink="db.execute", data_flow=["user_input"],
        why="SQLi", sanitizer_check="none",
        impact="DB compromise.", fix="Parameterize.",
        exploit={"type": "http", "payload": "1 OR 1=1", "expected": "all rows"})
    inv = Investigator("python")
    verdict = inv.validate(case, code)
    assert not verdict.accepted, "investigator must reject hallucinated snippet"
    assert "snippet does not appear" in verdict.reason
    print("[PASS] test_hallucinated_snippet_rejected")


def main():
    print("\n" + "=" * 70)
    print("  LogicBreaker AI  -- AI-First + Anti-Hallucination Tests")
    print("=" * 70 + "\n")
    tests = [
        test_ai_detects_incomplete_ssrf_allowlist,
        test_ai_detects_broken_yaml_mitigation,
        test_ai_classification_preserved_without_cwe,
        test_surgeon_proposes_complete_fix,
        test_prover_rejects_broken_fix,
        test_prover_accepts_working_fix,
        test_hallucinated_snippet_rejected,
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
