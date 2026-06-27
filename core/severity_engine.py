"""
Severity engine -- context-aware scoring (CVSS 1)
====================================================

Replaces the old static "this type is always HIGH" table. A finding's severity
is COMPUTED from the context the analyzers already gathered, using the official
CVSS 1 Base formula. The class's BASE vector comes from the VKB; context
SIGNALS (derived below) override individual metrics via the VKB modifiers.

The headline case the tool must get right: the SAME class can be Low or
Critical. A blind SSRF that only triggers an out-of-band callback is Low; an
SSRF that can reach cloud metadata and read IAM credentials is Critical. Both
are CWE-918 -- only the reachable impact differs, and that is exactly what the
modifiers + signals model.

Design rules:
  * Deterministic and auditable: every applied modifier records a reason, and we
    emit the final CVSS vector string so a human can re-check the score.
  * Never invents findings and never detects anything -- it scores findings the
    AST/taint engine already produced.
  * Signal derivation prefers STRUCTURED evidence (finding fields, sink text)
    over guessing; when unsure it leaves the base vector alone (conservative).
"""

from __future__ import annotations
import math
import re

from core import vkb


# ----------------------------------------------------------------------------
# 1) CVSS 1 Base score -- the official metric tables and equations.
#    Reference: FIRST CVSS 1 Specification, section 7.1.
# ----------------------------------------------------------------------------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}


def _roundup(x: float) -> float:
    """CVSS-specific round-up: ceiling to one decimal place, computed on integers
    to avoid binary float drift (per the 1 spec appendix)."""
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def cvss31_base(v: vkb.CVSSVector) -> float:
    """Compute the CVSS 1 Base Score (0.0-10.0) for a vector."""
    pr_table = _PR_CHANGED if v.S == "C" else _PR_UNCHANGED
    iss = 1 - (1 - _CIA[v.C]) * (1 - _CIA[v.I]) * (1 - _CIA[v.A])
    if v.S == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    exploitability = 8.22 * _AV[v.AV] * _AC[v.AC] * pr_table[v.PR] * _UI[v.UI]
    if impact <= 0:
        return 0.0
    if v.S == "U":
        return _roundup(min(impact + exploitability, 10.0))
    return _roundup(min(1.08 * (impact + exploitability), 10.0))


def rating(score: float) -> str:
    """Map a CVSS Base Score to the tool's severity labels."""
    if score <= 0.0:
        return "INFO"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


# ----------------------------------------------------------------------------
# 2) Context-signal derivation. We read the finding + the function source it
#    already carries and decide which named signals (matching VKB modifiers) are
#    active. These are CONTEXT signals on an ALREADY-DETECTED finding, not vuln
#    detection -- so light structural checks here are appropriate and safe.
# ----------------------------------------------------------------------------

# auth guard markers commonly seen upstream of a sink (decorators / checks).
_AUTH_MARKERS = [
    r"@login_required", r"@requires_auth", r"@auth\.", r"@jwt_required",
    r"current_user", r"session\[", r"session\.get\s*\(", r"g\.user",
    r"request\.user", r"is_authenticated", r"verify_jwt", r"@permission",
    r"check_auth", r"requires_login", r"@authenticated",
]
# internal / cloud-metadata indicators for SSRF severity.
_SENSITIVE_TARGET = [
    r"169\.254\.169\.254", r"metadata\.google", r"metadata\.azure",
    r"100\.100\.100\.200", r"127\.0\.0\.1", r"localhost", r"0\.0\.0\.0",
    r"10\.\d", r"192\.168\.", r"172\.(1[6-9]|2\d|3[01])\.",
    r"internal", r"\.local\b", r"/latest/meta-data", r"/computeMetadata",
]
# SQL write / DDL verbs -> integrity impact.
_SQL_WRITE = [r"\bINSERT\b", r"\bUPDATE\b", r"\bDELETE\b", r"\bDROP\b",
              r"\bALTER\b", r"\bTRUNCATE\b", r"\bCREATE\b", r"\bREPLACE\b",
              r"\bGRANT\b", r"\bMERGE\b"]


def derive_signals(finding: dict) -> tuple[set, bool]:
    """Inspect a finding dict and return (active_signal_names, confirmed).

    `finding` is the to_dict() form of a Finding (so this works for both Finding
    objects and the taint engine's raw dicts). `confirmed` means the dynamic
    sandbox actually proved exploitability (status CONFIRMED), which we use to
    sharpen confidence and to avoid a complexity downgrade.
    """
    src = (finding.get("source") or "") + "\n" + (finding.get("explanation") or "")
    src += "\n" + (finding.get("source_code") or "")
    evidence = (finding.get("source") or "") + " " + (finding.get("explanation") or "")
    cwe = finding.get("cwe", "")
    type_name = finding.get("type", "")
    status = (finding.get("status") or "").upper()
    proof = finding.get("dynamic_proof") or {}

    signals = set()
    confirmed = status == "CONFIRMED" or bool(proof.get("confirmed"))

    vc = vkb.resolve(cwe, type_name)
    available = set(vc.modifiers.keys())

    # --- auth context: is the sink gated behind authentication? -------------
    has_auth = any(re.search(p, src, re.I) for p in _AUTH_MARKERS)
    is_authz_class = vc.cwe in ("CWE-602", "CWE-639", "CWE-306", "CWE-287", "CWE-915")
    if "auth_required" in available and has_auth and not is_authz_class:
        signals.add("auth_required")
    if "no_auth" in available and not has_auth:
        signals.add("no_auth")

    # --- SSRF: sensitive target vs blind ------------------------------------
    if vc.cwe == "CWE-918":
        has_guard = bool(re.search(r"allowlist|whitelist|is_allowed|urlparse|"
                                   r"ipaddress|hostname\s+(in|not in)", src, re.I))
        if any(re.search(p, src, re.I) for p in _SENSITIVE_TARGET):
            signals.add("sensitive_target")
        elif not has_guard:
            # an unguarded user-controlled fetch can typically reach the internal
            # network; treat as internal-reachable unless evidence says blind.
            signals.add("internal_reachable")
        if re.search(r"\bblind\b|out[- ]of[- ]band|no\s+response|fire[- ]and[- ]forget", src, re.I):
            signals.discard("sensitive_target")
            signals.discard("internal_reachable")
            signals.add("blind")

    # --- SQL / Path: write vs read ------------------------------------------
    if vc.cwe == "CWE-89" and any(re.search(p, evidence, re.I) for p in _SQL_WRITE):
        signals.add("write_operation")
    if vc.cwe == "CWE-22" and re.search(r"open\s*\([^)]*['\"][wa]\+?['\"]|"
                                        r"['\"]\s*,\s*['\"][wa]", evidence):
        signals.add("write_operation")
    if vc.cwe == "CWE-639" and re.search(r"\.save\s*\(|\.delete\s*\(|\.update\s*\(|"
                                         r"INSERT|UPDATE|DELETE", evidence, re.I):
        signals.add("write_operation")

    # --- crypto used for passwords ------------------------------------------
    if vc.cwe == "CWE-327" and re.search(r"password|passwd|pwd|credential", src, re.I):
        signals.add("password_storage")

    # --- CORS with credentials ----------------------------------------------
    if vc.cwe == "CWE-942" and re.search(r"allow[_-]?credentials", src, re.I):
        signals.add("with_credentials")

    # --- race in a financial / inventory context ----------------------------
    if vc.cwe == "CWE-367" and re.search(r"balance|amount|stock|inventory|quantity|"
                                         r"wallet|credit|payment", src, re.I):
        signals.add("financial")

    # keep only signals this class actually defines a modifier for
    return (signals & available), confirmed


# ----------------------------------------------------------------------------
# 3) Public API: score one finding, and apply scoring across a list in place.
# ----------------------------------------------------------------------------
def score_finding(finding: dict) -> dict:
    """Return a scoring result for one finding dict:
        { severity, cvss_score, cvss_vector, cwe, parent_cwe, rationale[] }
    Pure function -- does not mutate the input."""
    cwe = finding.get("cwe", "")
    type_name = finding.get("type", "")
    vc = vkb.resolve(cwe, type_name)

    signals, confirmed = derive_signals(finding)

    vector = vc.base_vector
    rationale = [f"Base ({vc.cwe} {vc.cwe_name}): {vc.base_vector.string()}"]
    for sig in vc.modifiers:                      # insertion order = priority
        if sig in signals:
            mod = vc.modifiers[sig]
            vector = vector.with_overrides(mod.overrides)
            rationale.append(f"+ {sig}: {mod.reason}")

    score = cvss31_base(vector)
    sev = rating(score)
    if confirmed:
        rationale.append("Dynamically confirmed in sandbox -> confidence 1.0.")

    return {
        "severity": sev,
        "cvss_score": score,
        "cvss_vector": vector.string(),
        "cwe": vc.cwe,
        "parent_cwe": vc.parent_cwe,
        "fix_family": vc.fix_family,
        "confirmed": confirmed,
        "rationale": rationale,
    }


def apply_severity(findings, target_dir: str = "") -> None:
    """Re-score every Finding in `findings` IN PLACE from context. Safe to call
    at the end of a scan: it changes severity/confidence/CVSS fields only, never
    the set of findings, so detection accuracy is untouched.

    Accepts Finding dataclass objects (uses .to_dict() for reading, writes back
    attributes). Silently skips anything that doesn't look like a Finding."""
    for f in findings:
        try:
            data = f.to_dict() if hasattr(f, "to_dict") else dict(f)
        except Exception:
            continue
        res = score_finding(data)
        # write back (works for the Finding dataclass; ignore if frozen/other)
        try:
            f.severity = res["severity"]
            f.cvss_score = res["cvss_score"]
            f.cvss_vector = res["cvss_vector"]
            f.severity_rationale = res["rationale"]
            f.cwe = res["cwe"] or f.cwe
            if res["confirmed"]:
                f.confidence = 1.0
        except Exception:
            continue
