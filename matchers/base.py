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
    def _finding(matcher, unit, *, severity, confidence, explanation,
                 exploit_scenario="", remediation="", detection_method="static-heuristic"):
        return Finding(
            matcher_id=matcher.id,
            type=matcher.name,
            cwe=matcher.cwe,
            severity=severity,
            confidence=round(confidence, 2),
            file=unit["file"],
            language=unit["language"],
            function=unit.get("qualname", unit.get("name", "<module>")),
            lineno=unit.get("lineno", 0),
            end_lineno=unit.get("end_lineno", 0),
            source=unit.get("source", ""),
            explanation=explanation,
            exploit_scenario=exploit_scenario,
            remediation=remediation,
            detection_method=detection_method,
        )
