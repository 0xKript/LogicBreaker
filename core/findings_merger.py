"""
Findings Merger  --   Enterprise Merge Layer
================================================

PHILOSOPHY:
   runs 3 independent detection layers in parallel:
    1. Rule Engine (matchers)  -- fast regex-based detection
    2. Taint Engine             -- AST-based interprocedural tracking
    3. AI Detector              -- LLM-based deep analysis

  Each layer produces findings independently. The Merger:
    - De-duplicates findings (same file + CWE + line = one finding)
    - Cross-validates (multiple layers agreeing = higher confidence)
    - Ranks by severity + confidence
    - Records the source layer(s) for each finding (audit trail)

  This is the "single source of truth" the rest of the pipeline consumes.
  Without it, the same vuln could be reported 3x, and the AI Surgeon would
  waste time fixing the same issue 3x.

DESIGN:
  A finding is identified by (file, line, cwe) -- within a small line window
  (3 lines) to tolerate line-number drift between layers. Two findings with
  the same identity are merged:
    - confidence = max(confidence) + consensus_bonus
    - sources = [all layers that found it]
    - explanations = concatenated (the AI's is primary)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class MergedFinding:
    """A unified finding produced by merging results from multiple layers."""
    # identity (used for dedup)
    file: str
    line: int
    cwe: str

    # primary classification (taken from the highest-confidence source)
    name: str = ""
    severity: str = "MEDIUM"
    confidence: float = 0.0           # 0.0 - 1.0
    snippet: str = ""
    source: str = ""
    sink: str = ""
    data_flow: list = field(default_factory=list)
    why: str = ""
    impact: str = ""
    fix: str = ""
    exploit: dict = field(default_factory=dict)
    language: str = "python"

    #  metadata
    sources: List[str] = field(default_factory=list)  # ["matcher", "taint", "ai"]
    consensus_count: int = 0          # how many layers found it
    family: str = ""                  # "flow" | "property" | "broken-mitigation"
    category: str = ""

    # original finding objects (for audit trail)
    raw_findings: list = field(default_factory=list)

    @property
    def is_high_confidence(self) -> bool:
        """True if 2+ layers agreed on this finding (cross-validated)."""
        return self.consensus_count >= 2

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "cwe": self.cwe,
            "name": self.name,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "snippet": self.snippet,
            "source": self.source,
            "sink": self.sink,
            "why": self.why,
            "impact": self.impact,
            "fix": self.fix,
            "sources": self.sources,
            "consensus_count": self.consensus_count,
            "is_high_confidence": self.is_high_confidence,
            "family": self.family,
            "category": self.category,
        }


class FindingsMerger:
    """Merges findings from multiple detection layers.

    Usage:
        merger = FindingsMerger()
        merged = merger.merge(
            matcher_findings=[...],   # list of Finding objects (matchers.base)
            taint_findings=[...],     # list of dicts (taint engine)
            ai_findings=[...],        # list of CaseFile (ai_detector)
        )
    """

    # how close two findings' line numbers must be to count as the same finding
    LINE_WINDOW = 3

    # severity ranking (higher = more severe)
    _SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    def merge(self, matcher_findings=None, taint_findings=None,
              ai_findings=None) -> List[MergedFinding]:
        """Merge findings from all 3 layers. Returns a ranked list."""
        unified = []

        # normalise each layer's findings to a common shape
        if matcher_findings:
            for f in matcher_findings:
                unified.append(self._from_matcher(f))
        if taint_findings:
            for f in taint_findings:
                unified.append(self._from_taint(f))
        if ai_findings:
            for f in ai_findings:
                unified.append(self._from_ai(f))

        # deduplicate + cross-validate
        merged = self._deduplicate(unified)

        # rank by severity + confidence
        merged.sort(key=lambda m: (
            -self._SEV_RANK.get(m.severity, 0),
            -m.confidence,
            m.file, m.line,
        ))
        return merged

    # ---- normalisers -----------------------------------------------------

    def _from_matcher(self, f) -> MergedFinding:
        """Convert a matcher Finding (matchers.base) to MergedFinding."""
        return MergedFinding(
            file=getattr(f, "file", "") or "",
            line=int(getattr(f, "lineno", 0) or 0),
            cwe=(getattr(f, "cwe", "") or "").upper(),
            name=getattr(f, "type", "") or "",
            severity=(getattr(f, "severity", "MEDIUM") or "MEDIUM").upper(),
            confidence=float(getattr(f, "confidence", 0.5) or 0.5),
            snippet=getattr(f, "source", "") or "",
            source=getattr(f, "source", "") or "",
            sink="",
            why=getattr(f, "explanation", "") or "",
            impact=getattr(f, "impact", "") or "",
            fix=getattr(f, "remediation", "") or "",
            exploit={"scenario": getattr(f, "exploit_scenario", "") or ""},
            language=getattr(f, "language", "python") or "python",
            sources=["matcher"],
            consensus_count=1,
            raw_findings=[f],
        )

    def _from_taint(self, f) -> MergedFinding:
        """Convert a taint engine finding (dict) to MergedFinding."""
        if not isinstance(f, dict):
            f = {}
        cwe = (f.get("cwe") or "").upper()
        return MergedFinding(
            file=f.get("file", "") or "",
            line=int(f.get("lineno", 0) or 0),
            cwe=cwe,
            name=f.get("type", "") or "",
            severity=(f.get("severity", "MEDIUM") or "MEDIUM").upper(),
            confidence=float(f.get("confidence", 0.7) or 0.7),
            snippet=f.get("snippet", "") or "",
            source=f.get("source", "") or "",
            sink=f.get("sink", "") or "",
            data_flow=f.get("data_flow", []) or [],
            why=f.get("why", "") or f.get("explanation", "") or "",
            impact=f.get("impact", "") or "",
            fix=f.get("fix", "") or "",
            exploit=f.get("exploit", {}) or {},
            language=f.get("language", "python") or "python",
            sources=["taint"],
            consensus_count=1,
            raw_findings=[f],
        )

    def _from_ai(self, f) -> MergedFinding:
        """Convert an AI CaseFile to MergedFinding."""
        cwe = (getattr(f, "cwe", "") or "").upper()
        return MergedFinding(
            file=getattr(f, "file", "") or "",
            line=int(getattr(f, "line", 0) or 0),
            cwe=cwe,
            name=getattr(f, "name", "") or "",
            severity=(getattr(f, "severity", "MEDIUM") or "MEDIUM").upper(),
            confidence=float(getattr(f, "confidence", 70) or 70) / 100.0,
            snippet=getattr(f, "snippet", "") or "",
            source=getattr(f, "source", "") or "",
            sink=getattr(f, "sink", "") or "",
            data_flow=getattr(f, "data_flow", []) or [],
            why=getattr(f, "why", "") or "",
            impact=getattr(f, "impact", "") or "",
            fix=getattr(f, "fix", "") or "",
            exploit=getattr(f, "exploit", {}) or {},
            language=getattr(f, "language", "python") or "python",
            sources=["ai"],
            consensus_count=1,
            family=getattr(f, "family", "") or "",
            category=getattr(f, "category", "") or "",
            raw_findings=[f],
        )

    # ---- deduplication + cross-validation -------------------------------

    def _deduplicate(self, findings: List[MergedFinding]) -> List[MergedFinding]:
        """Merge findings with the same (file, cwe) within LINE_WINDOW lines.
        Cross-validation: each additional layer that found the same vuln
        boosts confidence."""
        if not findings:
            return []

        # group by (file, cwe) -- within line window
        groups: List[MergedFinding] = []
        for f in findings:
            # find a matching group
            matched = False
            for g in groups:
                if (g.file == f.file and g.cwe == f.cwe and
                        g.cwe and abs(g.line - f.line) <= self.LINE_WINDOW):
                    self._merge_into(g, f)
                    matched = True
                    break
            if not matched:
                groups.append(MergedFinding(
                    file=f.file, line=f.line, cwe=f.cwe,
                    name=f.name, severity=f.severity,
                    confidence=f.confidence,
                    snippet=f.snippet, source=f.source, sink=f.sink,
                    data_flow=f.data_flow, why=f.why, impact=f.impact,
                    fix=f.fix, exploit=f.exploit, language=f.language,
                    sources=list(f.sources),
                    consensus_count=f.consensus_count,
                    family=f.family, category=f.category,
                    raw_findings=list(f.raw_findings),
                ))
        return groups

    def _merge_into(self, target: MergedFinding, source: MergedFinding):
        """Merge `source` into `target` (in place). The highest-confidence
        finding's classification wins; consensus_count goes up; sources
        accumulate."""
        # take the higher-confidence classification
        if source.confidence > target.confidence:
            target.name = source.name
            target.severity = source.severity
            target.snippet = source.snippet
            target.source = source.source
            target.sink = source.sink
            target.data_flow = source.data_flow
            target.why = source.why or target.why
            target.impact = source.impact or target.impact
            target.fix = source.fix or target.fix
            target.exploit = source.exploit or target.exploit
            target.family = source.family or target.family
            target.category = source.category or target.category

        # always take the max severity (a HIGH from one layer + MEDIUM from
        # another -> HIGH)
        if self._SEV_RANK.get(source.severity, 0) > \
           self._SEV_RANK.get(target.severity, 0):
            target.severity = source.severity

        # accumulate sources (dedup)
        for s in source.sources:
            if s not in target.sources:
                target.sources.append(s)
                target.consensus_count += 1

        # consensus confidence boost: each additional layer = +0.10 (cap 1.0)
        if target.consensus_count >= 2:
            boost = 0.10 * (target.consensus_count - 1)
            target.confidence = min(1.0, max(target.confidence, source.confidence) + boost)

        # accumulate raw findings (audit trail)
        target.raw_findings.extend(source.raw_findings)
