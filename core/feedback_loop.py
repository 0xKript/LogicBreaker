"""
False Positive Feedback Loop  --   Enterprise
=================================================

Learns from analyst feedback to reduce false positives over time.

When an analyst marks a finding as a false positive, the tool:
  1. Records the pattern (file path pattern + CWE + snippet context)
  2. On subsequent scans, suppresses findings matching the pattern
  3. Reports how many FPs were suppressed (so the analyst sees the value)

This is REQUIRED for enterprise use -- without it, the analyst sees the
same false positives every run and loses trust in the tool.
"""

from __future__ import annotations

import os
import json
import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class FPPattern:
    """A learned false-positive pattern."""
    id: str                          # unique ID
    file_pattern: str                # regex matched against file path
    cwe: str                         # the CWE to suppress
    snippet_substring: str = ""      # if set, only suppress findings whose snippet contains this
    reason: str = ""                 # analyst's reason
    created_at: str = ""
    suppressions: int = 0            # how many times this pattern has suppressed a finding

    def matches(self, file_path: str, cwe: str, snippet: str = "") -> bool:
        """Check if a finding matches this FP pattern."""
        if (cwe or "").upper() != self.cwe.upper():
            return False
        if not re.search(self.file_pattern, file_path, re.IGNORECASE):
            return False
        if self.snippet_substring and self.snippet_substring.lower() not in (snippet or "").lower():
            return False
        return True


class FeedbackLoop:
    """Manages false-positive feedback patterns.

    Usage:
        loop = FeedbackLoop()
        loop.mark_false_positive(file_path="utils/md5_cache.py", cwe="CWE-327",
                                  reason="MD5 used for cache key, not security")
        # ... later, during a scan:
        if loop.is_false_positive(file_path, cwe, snippet):
            # suppress this finding
    """

    def __init__(self, storage_path: str = ""):
        self.storage_path = storage_path or os.path.expanduser(
            "~/.logicbreaker/feedback.json")
        self.patterns: List[FPPattern] = []
        self._load()

    def _load(self):
        """Load patterns from disk."""
        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.patterns = [FPPattern(**p) for p in data.get("patterns", [])]
        except (OSError, ValueError, TypeError):
            self.patterns = []

    def _save(self):
        """Save patterns to disk."""
        try:
            os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
            data = {"patterns": [p.__dict__ for p in self.patterns]}
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        except OSError:
            pass  # best-effort

    def mark_false_positive(self, file_path: str, cwe: str,
                            reason: str = "", snippet: str = "") -> str:
        """Mark a finding as a false positive. Returns the pattern ID."""
        from datetime import datetime, timezone
        # build a file pattern from the path (use the basename + parent dir)
        # e.g. "/path/to/utils/md5_cache.py" -> "utils/md5_cache"
        parts = file_path.replace("\\", "/").split("/")
        if len(parts) >= 2:
            file_pattern = re.escape("/".join(parts[-2:]).rsplit(".", 1)[0])
        else:
            file_pattern = re.escape(file_path.rsplit(".", 1)[0])

        # extract a snippet substring if provided
        snippet_substring = ""
        if snippet:
            # take the first 30 chars of the snippet as the discriminator
            snippet_substring = snippet[:30].strip()

        pattern_id = f"fp_{len(self.patterns) + 1:04d}"
        pattern = FPPattern(
            id=pattern_id,
            file_pattern=file_pattern,
            cwe=(cwe or "").upper(),
            snippet_substring=snippet_substring,
            reason=reason,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self.patterns.append(pattern)
        self._save()
        return pattern_id

    def is_false_positive(self, file_path: str, cwe: str,
                          snippet: str = "") -> bool:
        """Check if a finding matches any known FP pattern. If yes, increment
        the suppression counter and return True."""
        for p in self.patterns:
            if p.matches(file_path, cwe, snippet):
                p.suppressions += 1
                return True
        return False

    def list_patterns(self) -> List[dict]:
        """Return all patterns as dicts (for reporting)."""
        return [p.__dict__ for p in self.patterns]

    def remove_pattern(self, pattern_id: str) -> bool:
        """Remove a pattern by ID."""
        before = len(self.patterns)
        self.patterns = [p for p in self.patterns if p.id != pattern_id]
        if len(self.patterns) < before:
            self._save()
            return True
        return False

    def clear(self):
        """Remove all patterns."""
        self.patterns = []
        self._save()
