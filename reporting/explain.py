"""
Plain-language helpers for the report
=====================================

This module intentionally contains NO catalogue of vulnerability types. Each
finding is explained using its OWN text: for AI-detected findings that text is
the model's own words (what / impact / fix), and for engine findings it comes
from the knowledge base. The only fixed text here is the meaning of the severity
LEVELS and the fix STATUS values -- those are stable concepts, not a list of
vulnerabilities, so the tool never depends on a predefined vuln list.
"""

SEVERITY_MEANING = {
    "CRITICAL": "An attacker could take over the system or access all data. Fix immediately.",
    "HIGH": "An attacker could steal data or seriously abuse the app. Fix as a priority.",
    "MEDIUM": "A real weakness that should be fixed, usually needing other conditions to exploit.",
    "LOW": "A minor issue or hardening gap. Worth fixing but lower urgency.",
}

STATUS_MEANING = {
    "VERIFIED_FIX": "Fixed and proven — the fix was applied and tested to confirm the issue is gone.",
    "LANGUAGE_PATCH": "Fixed automatically using a safe, known-good pattern.",
    "LLM_FIX": "Fix suggested by the AI (review before shipping).",
    "CONFIRMED": "Confirmed vulnerable — not yet fixed.",
    "AUTO_FIX_FAILED": "Could not be fixed automatically — needs a manual fix.",
    "LEFT_UNFIXED": "Left as-is (you chose not to fix, or no safe automatic fix exists).",
    "RECOMMENDATION": "No automatic fix — follow the recommended steps to fix it manually.",
}


def severity_meaning(sev):
    return SEVERITY_MEANING.get((sev or "").upper(), "")


def status_meaning(status):
    return STATUS_MEANING.get((status or "").upper(), "")
