"""
Confidence Scorer  --   Enterprise
=====================================

Computes a numeric confidence score (0-100) for each finding based on:
  - Consensus score (30 points max) -- how many AI passes + layers agreed
  - Anchor strength (25 points max) -- how well the snippet matches the line
  - Taint evidence (20 points max)  -- is there a clear source->sink flow?
  - Exploit proof (20 points max)   -- was the exploit verified by execution?
  - Self-critique (5 points max)    -- did the AI's self-critique keep it?

This gives the analyst a clear, defensible number to prioritise work.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ConfidenceBreakdown:
    """The confidence score broken down by component."""
    consensus_score: float = 0.0    # /30
    anchor_score: float = 0.0       # /25
    taint_score: float = 0.0        # /20
    exploit_score: float = 0.0      # /20
    critique_score: float = 0.0     # /5
    total: float = 0.0              # /100

    def to_dict(self) -> dict:
        return {
            "consensus": round(self.consensus_score, 1),
            "anchor": round(self.anchor_score, 1),
            "taint": round(self.taint_score, 1),
            "exploit": round(self.exploit_score, 1),
            "critique": round(self.critique_score, 1),
            "total": round(self.total, 1),
        }


class ConfidenceScorer:
    """Computes the confidence score for a finding."""

    def score(self, consensus_count: int = 1, n_passes: int = 3,
              anchor_matched: bool = True, anchor_ratio: float = 1.0,
              has_taint_flow: bool = False, has_source: bool = False,
              exploit_proven: bool = False, exploit_blocked_by_fix: bool = False,
              self_critique_ok: bool = True) -> ConfidenceBreakdown:
        """Compute the confidence score.

        Args:
            consensus_count: how many detection layers / AI passes found it
            n_passes: total number of AI passes (for normalisation)
            anchor_matched: did the snippet match a real line?
            anchor_ratio: the match ratio (0-1)
            has_taint_flow: is there a clear source->sink flow?
            has_source: is the source present in the file?
            exploit_proven: was the exploit verified by execution?
            exploit_blocked_by_fix: did the fix block the exploit?
            self_critique_ok: did the AI's self-critique keep it?
        """
        # ---- 1. Consensus (30 points) ----------------------------------
        # 3+ layers/passes agreeing = full 30 points
        # 2 = 20 points
        # 1 = 10 points
        if consensus_count >= 3:
            consensus_score = 30.0
        elif consensus_count == 2:
            consensus_score = 20.0
        else:
            consensus_score = 10.0

        # ---- 2. Anchor strength (25 points) ----------------------------
        if not anchor_matched:
            anchor_score = 0.0
        else:
            # exact match = 25, partial (>=70%) = 15-24
            if anchor_ratio >= 1.0:
                anchor_score = 25.0
            elif anchor_ratio >= 0.9:
                anchor_score = 22.0
            elif anchor_ratio >= 0.7:
                anchor_score = 15.0
            else:
                anchor_score = 5.0

        # ---- 3. Taint evidence (20 points) -----------------------------
        if has_taint_flow and has_source:
            taint_score = 20.0
        elif has_source:
            taint_score = 10.0
        else:
            # property vuln (no source needed) -- still gets full marks
            # because the primitive itself is the bug
            taint_score = 20.0

        # ---- 4. Exploit proof (20 points) ------------------------------
        if exploit_proven:
            exploit_score = 20.0
            if exploit_blocked_by_fix:
                exploit_score = 20.0  # max -- exploit proven AND fix proven
        else:
            exploit_score = 5.0  # detected but not executed

        # ---- 5. Self-critique (5 points) -------------------------------
        critique_score = 5.0 if self_critique_ok else 0.0

        total = (consensus_score + anchor_score + taint_score +
                 exploit_score + critique_score)
        # cap at 100
        total = min(100.0, total)

        return ConfidenceBreakdown(
            consensus_score=consensus_score,
            anchor_score=anchor_score,
            taint_score=taint_score,
            exploit_score=exploit_score,
            critique_score=critique_score,
            total=total,
        )

    def label(self, score: float) -> str:
        """Return a human-readable label for a confidence score."""
        if score >= 90:
            return "VERY HIGH"
        if score >= 75:
            return "HIGH"
        if score >= 50:
            return "MEDIUM"
        if score >= 25:
            return "LOW"
        return "VERY LOW"
