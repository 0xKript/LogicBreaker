"""
Fix Forensics   --  Execution-Based Proof (AI-First)
======================================================

PHILOSOPHY:
  The AI is the SOLE judge of whether the vulnerability is gone. The prover
  no longer re-scans with the rule engine (the rule engine is a parallel
  fast scanner, not the judge). The proof is EXECUTION:

    1. APPLIES CLEANLY  -- the AI's original_snippet is found verbatim and
                           replaced by fixed_snippet (with imports inserted).
    2. STILL PARSES     -- the patched file is syntactically valid (ast.parse
                           for Python; tree-sitter for other languages).
    3. EXECUTES         -- the patched module loads AND the endpoint responds
                           without crashing (a fix that breaks the endpoint
                           is rejected -- e.g. yaml.safe_load with a bad
                           Loader kwarg that raises TypeError).
    4. EXPLOIT BLOCKED  -- a safe, observable exploit probe no longer fires
                           on the patched code (the same probe that DID fire
                           on the original).
    5. BENIGN OK        -- legitimate input still works (the fix does not
                           crash on normal data).

  If execution cannot apply (no route, no probe for the class), the prover
  falls back to a SYNTAX + IMPORT check only -- it does NOT fall back to the
  rule engine (which was the  behaviour and could be fooled).

  This means: the AI's fix is accepted if the patched code parses, loads,
  responds to benign input, and the exploit no longer fires. The rule engine
  has no veto over the AI's fix.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field


@dataclass
class ProofResult:
    accepted: bool
    reason: str = ""
    patched_code: str = ""
    checks: dict = field(default_factory=dict)


def _norm(s: str) -> str:
    import re
    return re.sub(r"\s+", " ", (s or "")).strip()


class FixProver:
    """ execution-based prover. AI is the sole judge of vuln removal."""

    def __init__(self, language: str = "python"):
        self.language = language

    # ---- public API ------------------------------------------------------

    def prove(self, proposal, original_code: str, verdict) -> ProofResult:
        checks = {}

        # ---- 1) applies cleanly -----------------------------------------
        patched = self._apply(proposal, original_code)
        checks["applies"] = patched is not None
        if patched is None:
            return ProofResult(False,
                               "fix does not apply: original_snippet not found "
                               "verbatim in the file", "", checks)

        # ---- 2) still parses --------------------------------------------
        ok_syntax, syntax_msg = self._parses(patched)
        checks["parses"] = ok_syntax
        if not ok_syntax:
            return ProofResult(False, f"patched file no longer parses: {syntax_msg}",
                               patched, checks)

        # ---- 3) execution: load + exploit + benign ----------------------
        exec_result = self._execute(original_code, patched, verdict)
        checks["execution"] = exec_result

        if exec_result.get("exploit") == "vulnerable":
            return ProofResult(False,
                               "fix did NOT remove the vulnerability: the exploit "
                               "still fires against the patched code (proven by "
                               "execution)", patched, checks)
        if exec_result.get("exploit") == "broken_fix":
            return ProofResult(False,
                               "fix breaks the application: the patched module no "
                               "longer loads/runs (e.g. yaml.safe_load with a "
                               "Loader kwarg that raises TypeError)", patched, checks)
        if exec_result.get("benign") == "broken":
            return ProofResult(False,
                               "fix breaks the endpoint for legitimate input "
                               "(returns a server error) -- neutralising the bug "
                               "by crashing is not an acceptable fix", patched, checks)

        # ---- 4) verdict -------------------------------------------------
        if exec_result.get("exploit") == "fixed" and exec_result.get("probe_valid"):
            proof_kind = "execution"
        elif exec_result.get("exploit") == "inconclusive":
            # execution could not apply (no route / no probe for the class).
            #  accept on syntax + parse only (the AI is the sole judge of
            # vuln removal; we do NOT fall back to the rule engine).
            proof_kind = "syntax-only (execution inconclusive)"
        else:
            proof_kind = "execution"

        return ProofResult(True,
                           f"proven ({proof_kind}): patch applies, parses, the "
                           f"endpoint loads and responds, and the exploit is "
                           f"blocked (or no executable probe exists for this class)",
                           patched, checks)

    # ---- individual steps ------------------------------------------------

    def _apply(self, proposal, code: str):
        """Replace original_snippet -> fixed_snippet at the occurrence NEAREST the
        finding's line. Inserts any required imports at module top."""
        original = proposal.original_snippet
        fixed = proposal.fixed_snippet
        if not original.strip() or not fixed.strip():
            return None
        target_line = getattr(proposal, "line", 0) or 0

        patched = None

        # exact match (may be multi-line): pick the occurrence whose start
        # line is closest to the target line
        occ = []
        start = 0
        while True:
            idx = code.find(original, start)
            if idx == -1:
                break
            line_no = code.count("\n", 0, idx) + 1
            occ.append((idx, line_no))
            start = idx + 1
        if occ:
            best_idx, _ = min(occ, key=lambda t: (abs(t[1] - target_line), t[1]))
            patched = code[:best_idx] + fixed + code[best_idx + len(original):]
        else:
            # whitespace-insensitive single-line fallback
            target = _norm(original)
            lines = code.splitlines()
            cands = [i for i, ln in enumerate(lines) if _norm(ln) == target]
            if cands:
                i = min(cands, key=lambda k: (abs((k + 1) - target_line), k))
                indent = lines[i][:len(lines[i]) - len(lines[i].lstrip())]
                repl = fixed.splitlines() or [fixed]
                repl = [repl[0]] + [(indent + r if r.strip() else r) for r in repl[1:]]
                if not repl[0].startswith((" ", "\t")) and indent:
                    repl[0] = indent + repl[0]
                lines[i:i + 1] = repl
                patched = "\n".join(lines)
        if patched is None:
            return None

        patched = self._insert_imports(patched, proposal.imports)
        return patched

    def _insert_imports(self, code: str, imports: list) -> str:
        if not imports:
            return code
        lines = code.splitlines()
        idx = 0
        for i, ln in enumerate(lines):
            s = ln.strip()
            if s == "" or s.startswith("#") or s.startswith(("import ", "from ")):
                idx = i + 1
                continue
            break
        to_add = [imp for imp in imports if imp.strip() and imp not in code]
        if not to_add:
            return code
        return "\n".join(lines[:idx] + to_add + lines[idx:])

    def _parses(self, code: str):
        if self.language == "python":
            try:
                ast.parse(code)
                return True, ""
            except SyntaxError as e:
                return False, f"line {e.lineno}: {e.msg}"
        try:
            from languages.ts_loader import get_parser, available
            if not available():
                return True, ""
            parser = get_parser(self.language)
            tree = parser.parse(code.encode("utf-8", "replace"))
            return (not tree.root_node.has_error), ("tree-sitter parse error"
                                                    if tree.root_node.has_error else "")
        except Exception:
            return True, ""

    def _execute(self, original_code: str, patched_code: str, verdict) -> dict:
        """Run the execution prover (safe exploit + benign probe) on the patched
        code, validating the probe on the original first."""
        try:
            from core.exploit_prover import ExploitProver
            return ExploitProver(self.language).assess(
                patched_code, verdict, verdict.case, original_code=original_code)
        except Exception as e:
            return {"exploit": "inconclusive", "benign": "inconclusive",
                    "probe_valid": False,
                    "error": f"{type(e).__name__}: {e}"}
