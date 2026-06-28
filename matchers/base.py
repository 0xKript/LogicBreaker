"""
Matcher framework (plugin system)
=================================

A "matcher" is a self-contained detector for one class of vulnerability.
Each matcher declares:

  * an ``id`` and ``name`` and ``cwe`` reference,
  * the languages it understands,
  * a ``match(unit, context)`` method returning a list of ``Finding`` objects.

New attack types are added simply by dropping a new ``BaseMatcher`` subclass
into ``matchers/`` and registering it -- no changes to the engine. This is
the extension point that lets the tool grow to cover more of the OWASP /
CWE catalogue over time.

Matchers operate on the *generic* code-unit representation produced by the
tree-sitter parser (name, params, source text, language), so a single
matcher can flag the same logic flaw across many languages by reasoning over
syntax-tree-derived signals and language-aware keyword/operator tables rather
than one language's AST only.
"""

import re
from dataclasses import dataclass, field, asdict
from typing import List, Optional


@dataclass
class Finding:
    matcher_id: str
    type: str
    cwe: str
    severity: str            # CRITICAL | HIGH | MEDIUM | LOW
    confidence: float        # 0..1
    file: str
    language: str
    function: str
    lineno: int
    end_lineno: int
    source: str
    explanation: str
    exploit_scenario: str = ""
    remediation: str = ""
    impact: str = ""             # plain-language real-world risk (AI findings)
    detection_method: str = "static-heuristic"
    status: str = "STATIC_FINDING"
    dynamic_proof: Optional[dict] = None
    suggested_fix: Optional[dict] = None
    # Context-aware severity (computed by core.severity_engine from CVSS 1).
    cvss_score: float = 0.0
    cvss_vector: str = ""
    severity_rationale: list = field(default_factory=list)
    # LLM layer (Phases C/E): the evidence the LLM is forced to return
    # (line/source/sink/sanitizer_present), and a note recording any
    # reclassification the LLM applied to the engine's type/cwe/severity.
    evidence: Optional[dict] = None
    reclassified: str = ""
    # Phase F: the Wise Verdict's decisive ruling {ruling, reason, confidence,
    # sources}. Phase G: CVE/CWE enrichment {description, mitigations, ...}.
    verdict: Optional[dict] = None
    enrichment: Optional[dict] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class ScanContext:
    """Shared, read-only context passed to every matcher call."""
    target_dir: str
    all_units: list = field(default_factory=list)
    routes: list = field(default_factory=list)
    llm: object = None


class BaseMatcher:
    id = "base"
    name = "Base Matcher"
    cwe = ""
    languages = set()          # empty = all languages
    default_severity = "MEDIUM"

    def supports(self, language: str) -> bool:
        return not self.languages or language in self.languages

    def match(self, unit: dict, context: ScanContext) -> List[Finding]:
        raise NotImplementedError

    # -- helpers shared by subclasses ---------------------------------
    @staticmethod
    def _find_line_in_unit(unit, pattern, flags=0):
        """Resolve the ACTUAL line number (1-based, in the file) of the first
        line in the unit's source that matches `pattern`.

        BUG FIX: previously the matchers reported `unit['lineno']` (the
        function-definition start line) for every finding inside that function.
        So a SQL injection on line 115 inside a function starting on line 110
        was reported as 'line 110'. This helper walks the unit's own source
        (which tree-sitter guarantees starts at `unit['lineno']`) and returns
        the precise file line of the match.

        Returns `unit['lineno']` (function start) as a safe fallback when the
        pattern doesn't match -- preserves backwards compatibility for any
        matcher that passes a wrong/missing pattern.
        """
        func_start = unit.get("lineno", 0) or 0
        src = unit.get("source", "") or ""
        if not src:
            return func_start
        try:
            rx = re.compile(pattern, flags)
        except re.error:
            return func_start
        for i, line in enumerate(src.split("\n")):
            if rx.search(line):
                return func_start + i
        return func_start  # fallback: function start (old behaviour)

    @staticmethod
    def _finding(matcher, unit, *, severity, confidence, explanation,
                 exploit_scenario="", remediation="",
                 detection_method="static-heuristic",
                 anchor_pattern=None, anchor_flags=0):
        """Build a Finding.

        `anchor_pattern` (optional regex, str OR list[str]): if provided, the
        finding's `lineno` is resolved to the FIRST line inside the unit's
        source that matches the pattern. This is the FIX for the long-standing
        bug where matchers reported the function-start line for every finding.
        If the pattern doesn't match (or isn't provided), we fall back to
        `unit['lineno']` (function start) to preserve backwards compatibility.
        """
        func_start = unit.get("lineno", 0) or 0
        lineno = func_start
        if anchor_pattern is not None:
            patterns = anchor_pattern if isinstance(anchor_pattern, list) else [anchor_pattern]
            for pat in patterns:
                resolved = BaseMatcher._find_line_in_unit(unit, pat, anchor_flags)
                if resolved != func_start:
                    lineno = resolved
                    break
        return Finding(
            matcher_id=matcher.id,
            type=matcher.name,
            cwe=matcher.cwe,
            severity=severity,
            confidence=round(confidence, 2),
            file=unit["file"],
            language=unit["language"],
            function=unit.get("qualname", unit.get("name", "<module>")),
            lineno=lineno,
            end_lineno=unit.get("end_lineno", 0),
            source=unit.get("source", ""),
            explanation=explanation,
            exploit_scenario=exploit_scenario,
            remediation=remediation,
            detection_method=detection_method,
        )
