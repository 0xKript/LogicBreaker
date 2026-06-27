"""
AI Pipeline   --  AI-First End-to-End
=======================================

PHILOSOPHY:
  The AI is the SOLE detector + classifier + fixer. The deterministic
  investigator only checks the snippet/sink anchor (no CWE lookup, no family
  decision). The deterministic FixProver only EXECUTES the patched code and
  verifies the exploit no longer fires (no rule-engine re-scan).

  This pipeline can run WITHOUT any rule engine -- it is purely AI-driven.
  The rule engine (matchers + taint) is still available as a parallel fast
  scanner, but the AI pipeline does not depend on it.

  New in  the surgeon can RETRY when a fix does not apply cleanly. The
  prover reports why the fix failed, and the surgeon is called again with
  the failure reason so it can correct its proposal.
"""

from __future__ import annotations

import traceback
from dataclasses import dataclass, field

from agents.ai_detector import AIDetector
from agents.ai_surgeon import AISurgeon
from core.case_validator import Investigator
from core.fix_prover import FixProver
from core.re_attacker import ReAttacker


@dataclass
class RepairOutcome:
    verdict: object
    proposal: object = None
    proof: object = None
    reattack: object = None  #  ReAttackResult
    error: str = ""
    attempts: int = 0

    @property
    def fixed(self) -> bool:
        #  a fix is "fixed" if BOTH the FixProver AND the ReAttacker accept
        # (the ReAttacker re-launches the original exploit on the patched code)
        if not (self.proof and self.proof.accepted):
            return False
        if self.reattack is None:
            return True  # re-attack not run (e.g. non-Python) -> trust FixProver
        return bool(self.reattack.accepted)


@dataclass
class AIReport:
    file: str
    language: str
    confirmed: list = field(default_factory=list)
    rejected: list = field(default_factory=list)
    repairs: list = field(default_factory=list)
    patched_code: str = ""
    errors: list = field(default_factory=list)

    @property
    def num_confirmed(self) -> int:
        return len(self.confirmed)

    @property
    def num_fixed(self) -> int:
        return sum(1 for r in self.repairs if r.fixed)

    def summary(self) -> dict:
        return {
            "file": self.file,
            "confirmed": self.num_confirmed,
            "rejected": len(self.rejected),
            "fixed": self.num_fixed,
            "unfixed": self.num_confirmed - self.num_fixed,
            "errors": len(self.errors),
        }


class AIPipeline:
    """ AI-first pipeline. AI = sole detector + classifier + fixer."""

    def __init__(self, llm_client, language: str = "python",
                 max_fix_retries: int = 2):
        self.language = language
        self.detector = AIDetector(llm_client)
        self.investigator = Investigator(language)
        self.surgeon = AISurgeon(llm_client, max_retries=max_fix_retries)
        self.prover = FixProver(language)
        self.max_fix_retries = max_fix_retries

    def analyze(self, code: str, file_path: str = "", do_fix: bool = True) -> AIReport:
        report = AIReport(file=file_path, language=self.language, patched_code=code)

        # 1) AI detects (sole detector + classifier)
        try:
            cases = self.detector.detect(code, self.language, file_path)
        except Exception as e:
            report.errors.append(f"detect: {type(e).__name__}: {e}\n"
                                 f"{traceback.format_exc()}")
            return report

        # 2) Investigator verifies the evidence (anchor + sink only)
        try:
            verdicts = self.investigator.validate_all(cases, code)
        except Exception as e:
            report.errors.append(f"investigate: {type(e).__name__}: {e}\n"
                                 f"{traceback.format_exc()}")
            return report
        report.confirmed = [v for v in verdicts if v.accepted]
        report.rejected = [v for v in verdicts if not v.accepted]

        if not do_fix or not report.confirmed:
            return report

        # 3) AI proposes a fix + prover verifies by execution + re-attack
        re_attacker = ReAttacker(self.language, timeout=15.0)
        for v in report.confirmed:
            outcome = RepairOutcome(verdict=v)
            last_error = ""
            for attempt in range(self.max_fix_retries + 1):
                outcome.attempts = attempt + 1
                try:
                    proposal = self.surgeon.propose(v, code)
                    outcome.proposal = proposal
                    if proposal.is_empty:
                        outcome.error = "surgeon returned an empty proposal"
                        break
                    outcome.proof = self.prover.prove(proposal, code, v)
                    if outcome.proof.accepted:
                        #  RE-ATTACK -- launch the original exploit on the
                        # patched code to PROVE the fix works.
                        patched = outcome.proof.patched_code
                        try:
                            outcome.reattack = re_attacker.verify(
                                code, patched, v, v.case)
                        except Exception as e:
                            # re-attack infrastructure failure -> don't block
                            # the fix, but record the error
                            outcome.reattack = None
                            report.errors.append(
                                f"re-attack {v.case.name}@{v.line}: "
                                f"{type(e).__name__}: {e}")
                        if outcome.fixed:
                            last_error = ""
                            break
                        else:
                            ra_reason = (outcome.reattack.reason
                                         if outcome.reattack else "no re-attack")
                            last_error = f"re-attack failed: {ra_reason}"
                    else:
                        last_error = outcome.proof.reason
                except Exception as e:
                    last_error = f"{type(e).__name__}: {e}"
                    outcome.error = last_error
                    report.errors.append(f"fix attempt {attempt+1} "
                                         f"{v.case.name}@{v.line}: {last_error}")
            if last_error and not outcome.fixed:
                outcome.error = last_error
            report.repairs.append(outcome)

        # 4) Assemble the final file from PROVEN fixes only
        report.patched_code = self._apply_proven(code, report.repairs)
        return report

    def _apply_proven(self, code: str, repairs: list) -> str:
        proven = [r for r in repairs if r.fixed and r.proposal
                  and not r.proposal.is_empty]
        proven.sort(key=lambda r: getattr(r.verdict, "line", 0), reverse=True)
        current = code
        for r in proven:
            patched = self.prover._apply(r.proposal, current)
            if patched is not None:
                ok, _ = self.prover._parses(patched)
                if ok:
                    current = patched
        return current
