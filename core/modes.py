"""
Offline Mode + Deterministic Mode  --   Enterprise
=====================================================

Offline Mode:
  When the LLM is unavailable (network down, API key invalid, rate limit),
  the tool falls back to the rule engine (matchers + taint) instead of
  crashing. Findings are flagged "engine-only" (lower confidence).

  This is REQUIRED for air-gapped government environments.

Deterministic Mode:
  Forces temperature=0 on every LLM call AND disables any source of
  randomness (time-based seeds, random sampling). The same code always
  produces the same findings, in the same order, with the same confidence.

  This is REQUIRED for:
    - Audit trail reproducibility (SOC 2)
    - CI/CD gates (a passing build must keep passing)
    - Regression testing (compare two runs)
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class OfflineMode:
    """Configuration for offline mode."""
    enabled: bool = False
    reason: str = ""

    @classmethod
    def from_env(cls) -> "OfflineMode":
        """Read offline mode from env vars."""
        if os.environ.get("LB_OFFLINE", "") in ("1", "true", "True"):
            return cls(enabled=True, reason="LB_OFFLINE=1")
        if not os.environ.get("LB_TEST_API_KEY") and not os.environ.get(
                "OPENAI_API_KEY") and not os.environ.get("GROQ_API_KEY") \
                and not os.environ.get("ANTHROPIC_API_KEY"):
            return cls(enabled=True, reason="no LLM API key in env")
        return cls(enabled=False)

    def should_use_engine_only(self, llm_client=None) -> bool:
        """True if we should skip the AI and use only the rule engine."""
        if self.enabled:
            return True
        if llm_client is None or not getattr(llm_client, "available", False):
            return True
        return False


@dataclass
class DeterministicMode:
    """Configuration for deterministic mode (always on by default)."""
    temperature: float = 0.0
    seed: int = 0
    sort_findings: bool = True  # sort findings by (severity, confidence, file, line)
    dedupe: bool = True         # deduplicate findings

    @classmethod
    def from_env(cls) -> "DeterministicMode":
        """Read deterministic mode from env vars."""
        # Deterministic mode is ALWAYS on by default. Set LB_NON_DETERMINISTIC=1
        # to disable (not recommended for production).
        if os.environ.get("LB_NON_DETERMINISTIC", "") in ("1", "true", "True"):
            return cls(temperature=0.1, seed=None, sort_findings=False, dedupe=False)
        return cls()

    def apply_to_llm_kwargs(self, kwargs: dict) -> dict:
        """Force temperature=0 in LLM call kwargs."""
        kwargs["temperature"] = self.temperature
        return kwargs
