"""
Priority Queue  --   Enterprise
==================================

Sorts files by security priority so critical files (auth, payment, admin)
are scanned first. This gives the analyst the most important findings
within the first 30 seconds, even on a 1000-file batch.
"""

from __future__ import annotations

from typing import List


# Files matching these patterns are HIGH priority (scan first)
HIGH_PRIORITY_PATTERNS = [
    "auth", "login", "session", "token", "password", "passwd",
    "payment", "checkout", "billing", "credit", "card", "stripe", "paypal",
    "admin", "root", "privilege", "permission", "rbac", "acl",
    "upload", "download", "import", "export",
    "api_key", "secret", "key", "cert",
    "user", "account", "profile", "register",
]

# Files matching these patterns are MEDIUM priority
MEDIUM_PRIORITY_PATTERNS = [
    "config", "settings", "env", "database", "db", "model", "schema",
    "route", "controller", "handler", "view", "endpoint",
    "middleware", "filter", "interceptor",
]


class PriorityQueue:
    """Sorts files by security priority.

    High priority = auth/payment/admin (scan first)
    Medium priority = config/routes/models
    Low priority = tests/utils/docs
    """

    def __init__(self, high_patterns=None, medium_patterns=None):
        self.high_patterns = [p.lower() for p in (high_patterns or HIGH_PRIORITY_PATTERNS)]
        self.medium_patterns = [p.lower() for p in (medium_patterns or MEDIUM_PRIORITY_PATTERNS)]

    def priority(self, file_path: str) -> int:
        """Return 1 (high), 2 (medium), or 3 (low)."""
        path_lower = file_path.lower()
        for p in self.high_patterns:
            if p in path_lower:
                return 1
        for p in self.medium_patterns:
            if p in path_lower:
                return 2
        return 3

    def sort(self, files: List[dict]) -> List[dict]:
        """Sort files by priority (high first)."""
        return sorted(files, key=lambda f: (
            self.priority(f.get("rel_path", f.get("path", ""))),
            f.get("rel_path", f.get("path", "")),
        ))
