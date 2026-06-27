"""
AI Surgeon   --  AI-First Deep Repair
========================================

PHILOSOPHY:
  The AI is the SOLE fixer. It analyzes the vulnerability deeply, including
  INCOMPLETE MITIGATIONS and BROKEN MITIGATIONS, and proposes a COMPLETE fix
  that closes every bypass the AI identified. The AI is explicitly told to:

    * Understand WHY the original code is vulnerable (the root cause, not the
      symptom).
    * If the original has a partial defence (e.g. SSRF allowlist that misses
      172.16.0.0/12), REPLACE it with a complete defence -- do not patch the
      existing check piecemeal.
    * If the original has a broken mitigation (e.g. yaml.safe_load with a
      Loader kwarg that raises TypeError), fix the CALL so it works correctly.
    * Verify the fix does not break legitimate functionality.
    * Verify the fix does not introduce a new vulnerability.

  The deterministic FixProver (core/fix_prover.py) still exists, but only to
    EXECUTE the patched code and prove the exploit no longer fires. It no
  longer re-scans with the rule engine -- the AI is the judge of whether the
  vulnerability is gone, and execution is the proof.

ANTI-HALLUCINATION (kept):
  * The fix proposal must include the verbatim original_snippet (to be
    replaced) and the verbatim fixed_snippet (the replacement). The prover
    applies the replacement and verifies the patched file parses + runs + the
    exploit no longer fires.
  * If the AI's fix does not apply cleanly (original_snippet not found), it is
    rejected and the AI is asked to try again (up to N retries).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RepairProposal:
    """The AI's proposed fix for one confirmed vulnerability. Unproven until
    the FixProver validates it by execution."""
    original_snippet: str          # exact text to replace (must match the file)
    fixed_snippet: str             # the replacement, verbatim
    imports: list                  # module-level imports the fix needs
    explanation: str               # human summary of the change
    strength_notes: str            # why it is robust, not a band-aid
    #  the AI's analysis of the root cause + the specific bypasses it closes
    root_cause: str = ""
    bypasses_closed: str = ""
    cwe: str = ""
    line: int = 0
    raw: dict = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        return not self.fixed_snippet.strip()

    def to_dict(self) -> dict:
        return {
            "original_snippet": self.original_snippet,
            "fixed_snippet": self.fixed_snippet,
            "imports": list(self.imports),
            "explanation": self.explanation,
            "strength_notes": self.strength_notes,
            "root_cause": self.root_cause,
            "bypasses_closed": self.bypasses_closed,
            "cwe": self.cwe,
            "line": self.line,
        }


def build_fix_prompt(verdict, code: str) -> tuple[str, str]:
    """ fix prompt: deep root-cause analysis + complete fix.

    The AI is told to:
      1. Explain the ROOT CAUSE (why the code is vulnerable).
      2. List the SPECIFIC BYPASSES the fix must close (for an incomplete
         mitigation, this is the gap list; for a property vuln, this is the
         attack vector).
      3. Provide a COMPLETE fix that closes every bypass.
      4. Verify the fix does not break legitimate functionality.
      5. Verify the fix does not introduce a new vulnerability.
    """
    case = verdict.case
    numbered = "\n".join(
        f"{i}| {ln}" for i, ln in enumerate(code.splitlines(), 1)
    )
    system = (
        "You are a senior secure-coding engineer. You are given ONE confirmed "
        "vulnerability and must produce a COMPLETE, root-cause fix -- never a "
        "cosmetic or partial one.\n\n"
        "Your fix must:\n"
        "  (a) FULLY neutralize the vulnerability -- close EVERY bypass the\n"
        "      detector identified. If the original has a partial defence\n"
        "      (e.g. an SSRF allowlist that misses 172.16.0.0/12, IPv6 ULA,\n"
        "      DNS rebinding, decimal IP, redirects), REPLACE it with a\n"
        "      complete defence. Do NOT patch the existing check piecemeal.\n"
        "  (b) If the original has a BROKEN mitigation (e.g. calling\n"
        "      yaml.safe_load(data, Loader=yaml.Loader) which raises\n"
        "      TypeError), fix the CALL so it works correctly\n"
        "      (yaml.safe_load(data) without the Loader kwarg).\n"
        "  (c) Preserve the code's behavior for legitimate input -- do not\n"
        "      break the endpoint for normal users.\n"
        "  (d) Be valid, idiomatic code.\n"
        "  (e) Introduce NO new vulnerability.\n\n"
        "Your fix will be APPLIED to the real file, then EXECUTED against a\n"
        "real exploit probe. A fix that does not actually remove the\n"
        "vulnerability, OR that crashes the endpoint, OR that breaks legitimate\n"
        "input will be detected and rejected. So make the fix genuinely\n"
        "correct, not merely plausible-looking.\n\n"
        "Respond with STRICT JSON only -- no prose, no markdown fences."
    )
    user = (
        f"Confirmed vulnerability to fix:\n"
        f"  name: {case.name}\n"
        f"  cwe: {verdict.cwe or '(none)'}\n"
        f"  category: {getattr(case, 'category', '')}\n"
        f"  family: {getattr(case, 'family', '')}\n"
        f"  line: {verdict.line}\n"
        f"  vulnerable code: {case.snippet!r}\n"
        f"  why it is exploitable: {case.why}\n"
        f"  dangerous sink: {case.sink!r}\n"
        f"  AI's sanitizer analysis: {case.sanitizer_check}\n"
        f"  AI's impact assessment: {case.impact}\n\n"
        "Return a single JSON object of EXACTLY this shape:\n"
        "{\n"
        '  "root_cause": "<one or two sentences: the ROOT CAUSE, not the symptom>",\n'
        '  "bypasses_closed": "<the specific bypasses/attacks this fix closes; comma-separated>",\n'
        '  "original_snippet": "<the exact line(s) to replace, copied VERBATIM from the file -- must match character-for-character>",\n'
        '  "fixed_snippet": "<the replacement line(s); complete fix; same indentation; valid code>",\n'
        '  "imports": ["<any module-level import the fix needs, e.g. import ipaddress>"],\n'
        '  "explanation": "<one or two sentences: what you changed>",\n'
        '  "strength_notes": "<why this is a robust root-cause fix and not a band-aid>"\n'
        "}\n\n"
        "Rules:\n"
        "1. `original_snippet` MUST occur verbatim in the file so it can be\n"
        "   replaced exactly.\n"
        "2. For an INCOMPLETE MITIGATION (e.g. partial SSRF allowlist), include\n"
        "   the ENTIRE partial-defence block in original_snippet so the\n"
        "   complete replacement removes it. Do not just add a line on top.\n"
        "3. For a BROKEN MITIGATION (e.g. yaml.safe_load with Loader kwarg),\n"
        "   the fixed_snippet must be the correct call that actually works.\n"
        "4. If the fix needs a helper or import, put the import in `imports`.\n"
        "5. Keep indentation consistent with the original line.\n\n"
        f"FILE ({case.language}):\n"
        f"```{case.language}\n{numbered}\n```"
    )
    return system, user


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [str(x) for x in value if str(x).strip()]
    return []


def parse_repair(reply: dict, verdict) -> RepairProposal:
    if not isinstance(reply, dict):
        reply = {}
    return RepairProposal(
        original_snippet=str(reply.get("original_snippet", "")),
        fixed_snippet=str(reply.get("fixed_snippet", "")),
        imports=_as_list(reply.get("imports")),
        explanation=str(reply.get("explanation", "")).strip(),
        strength_notes=str(reply.get("strength_notes", "")).strip(),
        root_cause=str(reply.get("root_cause", "")).strip(),
        bypasses_closed=str(reply.get("bypasses_closed", "")).strip(),
        cwe=verdict.cwe,
        line=verdict.line,
        raw=reply,
    )


class AISurgeon:
    """ AI-first surgeon. The AI is the SOLE fixer."""

    def __init__(self, llm_client, max_tokens: int = 2048, timeout: float = 90.0,
                 max_retries: int = 2):
        self.llm = llm_client
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.max_retries = max_retries  # retry if the fix does not apply cleanly

    def propose(self, verdict, code: str) -> RepairProposal:
        if self.llm is None or not getattr(self.llm, "available", False):
            raise RuntimeError("AISurgeon  requires a configured LLM provider.")
        system, user = build_fix_prompt(verdict, code)
        reply = self.llm.chat_json(system, user,
                                   max_tokens=self.max_tokens, timeout=self.timeout)
        return parse_repair(reply, verdict)
