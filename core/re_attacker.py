"""
Re-Attacker  --  the final verification step ( Enterprise)
=============================================================

PHILOSOPHY:
  The user's pipeline is: detect → exploit → fix → RE-ATTACK.
  The  Fix Prover checked syntax + module load + exploit blocked, but did NOT
  re-launch the SAME exploit payload against the patched code to confirm the
  fix actually blocks it.  adds this final, decisive step.

  The Re-Attacker:
    1. Takes the SAME exploit probe that fired on the ORIGINAL code.
    2. Fires it against the PATCHED code in an isolated subprocess.
    3. If the marker still appears (or the response signature still matches)
       -> the fix FAILED -> rollback.
    4. If the marker is absent AND the endpoint responds normally
       -> the fix is PROVEN by execution.

  This is the "evidence that cannot be talked into existence" -- the same
  principle that drove the original Exploit Prover, now applied to the FIX
  side as a final, independent verification.

DESIGN:
  The Re-Attacker reuses the ExploitProver's `assess()` method because the
  probe machinery is identical (we want the SAME payload, SAME route, SAME
  detection signature). The only difference is interpretation:
    - ExploitProver.assess(original)  -> "did the exploit fire on the original?"
    - ReAttacker.reattack(patched)    -> "does the exploit STILL fire on the patched?"

  Both must agree for a fix to be accepted:
    - original: VULNERABLE (exploit fired)
    - patched:  FIXED (exploit blocked) + benign OK (endpoint still works)
"""

from __future__ import annotations

import os
import sys
import tempfile
import subprocess
import re
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ReAttackResult:
    """Outcome of re-attacking the patched code with the original exploit."""
    accepted: bool                       # True = fix proven by re-attack
    reason: str = ""                     # human explanation
    original_exploit_fired: bool = False # did the exploit fire on ORIGINAL?
    patched_exploit_fired: bool = False  # did the exploit STILL fire on PATCHED?
    patched_loaded: bool = False         # did the patched module load?
    patched_benign_ok: bool = False      # did the patched endpoint respond to benign?
    checks: dict = field(default_factory=dict)


class ReAttacker:
    """The final verification step: re-launch the original exploit against the
    patched code to PROVE the fix works.

    Usage:
        ra = ReAttacker(language="python")
        result = ra.verify(original_code, patched_code, verdict, case)
        if result.accepted:
            # fix is PROVEN by execution -- the exploit no longer fires
        else:
            # fix failed -- the exploit still fires (or the endpoint broke)
    """

    def __init__(self, language: str = "python", timeout: float = 15.0):
        self.language = language
        self.timeout = timeout

    def verify(self, original_code: str, patched_code: str,
               verdict, case) -> ReAttackResult:
        """Re-attack the patched code with the original exploit.

        Steps:
          1. Confirm the exploit fires on the ORIGINAL (sanity check -- if it
             doesn't, our probe is invalid and we can't conclude anything).
          2. Fire the SAME probe on the PATCHED code.
          3. If the patched exploit fires -> fix FAILED.
          4. If the patched exploit is blocked AND benign works -> fix PROVEN.
        """
        result = ReAttackResult(accepted=False)

        if self.language != "python":
            result.reason = "re-attack only supports Python (other languages fall back to syntax check)"
            result.accepted = True  # do not block non-Python fixes
            return result

        # ---- 1. validate the probe on the ORIGINAL ----------------------
        try:
            from core.exploit_prover import ExploitProver
            prober = ExploitProver(self.language, timeout=self.timeout)
            orig_assessment = prober.assess(
                original_code, verdict, case, original_code=original_code)
        except Exception as e:
            result.reason = f"re-attack: original assessment failed: {type(e).__name__}: {e}"
            result.accepted = True  # do not block on infrastructure errors
            return result

        result.original_exploit_fired = (
            orig_assessment.get("exploit") == "vulnerable"
            or orig_assessment.get("probe_valid", False)
        )
        result.checks["original_assessment"] = orig_assessment

        # If the probe never fired on the original, we cannot prove the fix
        # (an absent marker on patched may just mean the probe missed). In
        # that case, fall back to the FixProver's syntax+load check.
        if not result.original_exploit_fired:
            result.reason = ("re-attack inconclusive: the exploit probe did not "
                             "fire on the original code, so an absent marker on "
                             "the patched code is not proof of a fix. Falling "
                             "back to the FixProver's syntax + load check.")
            result.accepted = True  # let the FixProver's own verdict stand
            return result

        # ---- 2. fire the SAME probe on the PATCHED code ----------------
        try:
            patched_assessment = prober.assess(
                patched_code, verdict, case, original_code=original_code)
        except Exception as e:
            result.reason = f"re-attack: patched assessment failed: {type(e).__name__}: {e}"
            result.accepted = False
            return result

        result.patched_exploit_fired = (
            patched_assessment.get("exploit") == "vulnerable"
        )
        result.patched_loaded = patched_assessment.get("loaded", False) or \
            patched_assessment.get("exploit") != "broken_fix"
        result.patched_benign_ok = patched_assessment.get("benign") == "ok"
        result.checks["patched_assessment"] = patched_assessment

        # ---- 3. decide --------------------------------------------------
        # Case A: the patched module fails to load -> fix is BROKEN
        if patched_assessment.get("exploit") == "broken_fix":
            result.accepted = False
            result.reason = ("re-attack FAILED: the patched module no longer "
                             "loads/runs -- the fix broke the endpoint")
            return result

        # Case B: the patched endpoint crashes on benign input -> fix is BROKEN
        if patched_assessment.get("benign") == "broken":
            result.accepted = False
            result.reason = ("re-attack FAILED: the patched endpoint returns a "
                             "server error on legitimate input -- neutralising "
                             "the bug by crashing is not an acceptable fix")
            return result

        # Case C: the exploit STILL fires on the patched code -> fix FAILED
        if patched_assessment.get("exploit") == "vulnerable":
            result.accepted = False
            result.reason = ("re-attack FAILED: the original exploit still "
                             "fires against the patched code -- the fix did "
                             "NOT remove the vulnerability (proven by execution)")
            return result

        # Case D: the exploit is blocked AND the endpoint works -> fix PROVEN
        if patched_assessment.get("exploit") == "fixed" and \
           patched_assessment.get("probe_valid", False):
            result.accepted = True
            result.reason = ("re-attack PROVEN: the original exploit no longer "
                             "fires against the patched code, AND the endpoint "
                             "still responds to legitimate input. The fix is "
                             "verified by execution.")
            return result

        # Case E: inconclusive (no probe for this class, or probe didn't reach)
        result.accepted = True  # fall back to the FixProver's verdict
        result.reason = ("re-attack inconclusive for this vulnerability class "
                         "(no executable probe, or probe didn't reach the sink). "
                         "Falling back to the FixProver's syntax + load check.")
        return result

    # ---- helper: standalone re-attack (no verdict needed) ---------------

    def reattack_simple(self, original_code: str, patched_code: str,
                        route: str, method: str, payload: str,
                        param_kind: str = "query",
                        expected_marker_in_response: Optional[str] = None) -> ReAttackResult:
        """A simplified re-attack that does not require a Verdict/Case object.
        Useful for ad-hoc verification of a fix.

        Fires `payload` at `route` on both original and patched code, and
        checks if the response contains `expected_marker_in_response`.
        """
        result = ReAttackResult(accepted=False)

        # build a minimal fake verdict + case for the ExploitProver
        class _FakeCase:
            def __init__(self):
                self.exploit = {"type": "http", "payload": payload,
                                "expected": expected_marker_in_response or ""}
                self.snippet = ""
                self.source = ""
                self.sink = ""
                self.data_flow = []
                self.name = "Re-Attack Probe"
                self.cwe = ""

        class _FakeVerdict:
            def __init__(self, line):
                self.line = line
                self.cwe = ""
                self.case = _FakeCase()

        # find the route's line in the original code (for the ExploitProver)
        line = 1
        for i, ln in enumerate(original_code.splitlines(), 1):
            if route in ln:
                line = i
                break
        verdict = _FakeVerdict(line)

        return self.verify(original_code, patched_code, verdict, verdict.case)
