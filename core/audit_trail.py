"""
Audit Trail  --   Enterprise
===============================

Records every decision the tool makes, with timestamp + reason + confidence.

Required for:
  - SOC 2 Type II compliance (audit logs)
  - ISO 27001 (decision tracking)
  - Post-incident investigation (why was a finding accepted/rejected?)
  - Reproducibility (same code = same trail)

Each audit entry has:
  - timestamp (ISO 8601 UTC)
  - phase (detect / investigate / exploit / fix / re-attack)
  - action (e.g. "accepted", "rejected", "exploit_fired", "fix_proven")
  - target (file:line)
  - reason (human explanation)
  - confidence (0-1)
  - metadata (layer-specific details)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional


@dataclass
class AuditEntry:
    """A single audit-trail entry."""
    timestamp: str                    # ISO 8601 UTC
    phase: str                        # detect / investigate / exploit / fix / re-attack
    action: str                       # accepted / rejected / exploit_fired / fix_proven / etc.
    target: str                       # file:line
    reason: str = ""                  # human explanation
    confidence: float = 0.0           # 0-1
    layer: str = ""                   # matcher / taint / ai / investigator / prover / re-attacker
    metadata: dict = field(default_factory=dict)  # layer-specific details

    def to_dict(self) -> dict:
        return asdict(self)


class AuditTrail:
    """Collects audit entries throughout a pipeline run.

    Usage:
        trail = AuditTrail()
        trail.log(phase="detect", action="ai_detected",
                  target="app.py:25", reason="SQL Injection found",
                  confidence=0.95, layer="ai")
        ...
        trail.save("audit.json")
    """

    def __init__(self):
        self.entries: List[AuditEntry] = []
        self._start_time = datetime.now(timezone.utc)

    def log(self, phase: str, action: str, target: str,
            reason: str = "", confidence: float = 0.0,
            layer: str = "", **metadata):
        """Add an audit entry."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            phase=phase,
            action=action,
            target=target,
            reason=reason,
            confidence=round(float(confidence), 3),
            layer=layer,
            metadata=metadata,
        )
        self.entries.append(entry)
        return entry

    def log_detection(self, layer: str, target: str, finding_name: str,
                      cwe: str, confidence: float, **extra):
        """Convenience: log a detection event."""
        self.log(phase="detect", action=f"{layer}_detected",
                 target=target,
                 reason=f"{finding_name} ({cwe}) detected by {layer}",
                 confidence=confidence, layer=layer,
                 finding_name=finding_name, cwe=cwe, **extra)

    def log_investigation(self, target: str, accepted: bool, reason: str,
                          **extra):
        """Convenience: log an investigator decision."""
        self.log(phase="investigate",
                 action="accepted" if accepted else "rejected",
                 target=target, reason=reason,
                 confidence=1.0 if accepted else 0.0,
                 layer="investigator", **extra)

    def log_exploit(self, target: str, fired: bool, payload: str = "",
                    **extra):
        """Convenience: log an exploit prover event."""
        self.log(phase="exploit",
                 action="exploit_fired" if fired else "exploit_blocked",
                 target=target,
                 reason=f"exploit {'fired' if fired else 'blocked'} on probe",
                 confidence=1.0 if fired else 0.0,
                 layer="exploit_prover",
                 payload=payload, **extra)

    def log_fix(self, target: str, accepted: bool, reason: str, **extra):
        """Convenience: log a fix prover event."""
        self.log(phase="fix",
                 action="fix_proven" if accepted else "fix_failed",
                 target=target, reason=reason,
                 confidence=1.0 if accepted else 0.0,
                 layer="fix_prover", **extra)

    def log_reattack(self, target: str, blocked: bool, reason: str, **extra):
        """Convenience: log a re-attack event."""
        self.log(phase="re-attack",
                 action="reattack_blocked" if blocked else "reattack_failed",
                 target=target, reason=reason,
                 confidence=1.0 if blocked else 0.0,
                 layer="re-attacker", **extra)

    def summary(self) -> dict:
        """Return a summary of the audit trail."""
        phases = {}
        for e in self.entries:
            phases.setdefault(e.phase, {"count": 0, "actions": {}})
            phases[e.phase]["count"] += 1
            phases[e.phase]["actions"][e.action] = \
                phases[e.phase]["actions"].get(e.action, 0) + 1
        return {
            "total_entries": len(self.entries),
            "start_time": self._start_time.isoformat(),
            "end_time": datetime.now(timezone.utc).isoformat(),
            "phases": phases,
        }

    def to_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "entries": [e.to_dict() for e in self.entries],
        }

    def save(self, path: str):
        """Save the audit trail to a JSON file."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False,
                      default=str)

    def to_json(self) -> str:
        """Return the audit trail as a JSON string."""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False,
                          default=str)

    def filter_by_phase(self, phase: str) -> List[AuditEntry]:
        """Return only entries for a given phase."""
        return [e for e in self.entries if e.phase == phase]

    def filter_by_target(self, target: str) -> List[AuditEntry]:
        """Return only entries for a given target (file:line)."""
        return [e for e in self.entries if e.target == target]
