"""
Semgrep integration (Phase D -- complementary rule-based detection)
===================================================================

Runs the external `semgrep` tool as a subprocess (JSON output) ALONGSIDE the
taint engine, so ready-made community rules add coverage the engine doesn't model
(framework-specific patterns, language idioms). Results are normalised to the
same finding shape and merged + de-duplicated against engine findings by the
caller (see ScanEngine._merge_semgrep_findings).

Design notes / deliberate scope (per the implementation brief):
  * Semgrep is OPTIONAL. If it is not installed we return a sentinel so the
    caller prints one clear warning and continues ENGINE-ONLY -- never a crash.
  * We do NOT shell out to Psalm / PHPStan (they re-implement the taint engine
    we already have) or raw PHPCS (mostly style noise that would bury real
    bugs). Those would add cost and noise without new signal. If a user
    explicitly wants them, that is a separate, opt-in decision.
  * Rulesets default to broad security packs covering PHP / JS / Python /
    WordPress; override with the LB_SEMGREP_CONFIG env var (comma-separated).
"""

import json
import os
import re
import shutil
import subprocess

# semgrep severity (ERROR/WARNING/INFO) -> our scale
_SEV_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}

# Default rule configs. `p/...` are Semgrep Registry packs; "auto" lets semgrep
# choose by detected languages. Kept broad but security-focused (no style packs).
_DEFAULT_CONFIGS = ["p/php", "p/javascript", "p/python", "p/security-audit"]


def is_available():
    """True if the `semgrep` binary is on PATH."""
    return shutil.which("semgrep") is not None


def _configs():
    override = os.environ.get("LB_SEMGREP_CONFIG")
    if override:
        return [c.strip() for c in override.split(",") if c.strip()]
    return _DEFAULT_CONFIGS


def run_semgrep(target_dir, timeout=300):
    """Run semgrep over `target_dir` and return a list of normalised finding
    dicts. Returns None if semgrep is NOT installed (so the caller can warn and
    fall back to engine-only). Returns [] on any error/empty result -- a scan
    must never break because of the optional Semgrep layer."""
    if not is_available():
        return None

    cmd = ["semgrep", "--json", "--quiet", "--metrics", "off",
           "--timeout", "30", "--max-target-bytes", "2000000"]
    for cfg in _configs():
        cmd += ["--config", cfg]
    cmd.append(target_dir)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return []
    if not (proc.stdout or "").strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except Exception:
        return []

    out = []
    for r in data.get("results", []):
        norm = _normalize(r, target_dir)
        if norm:
            out.append(norm)
    return out


def _normalize(result, target_dir):
    """Map one semgrep result to our finding shape: file (relative), lineno,
    type, cwe, severity, message, check_id."""
    try:
        path = result.get("path", "")
        rel = os.path.relpath(path, target_dir) if path else ""
        line = int(((result.get("start") or {}).get("line")) or 0)
        extra = result.get("extra") or {}
        meta = extra.get("metadata") or {}
        sev = _SEV_MAP.get(str(extra.get("severity", "")).upper(), "MEDIUM")
        message = (extra.get("message") or "").strip()
        check_id = result.get("check_id", "")

        # CWE + class name: metadata.cwe is usually like "CWE-89: SQL Injection"
        # (string or list). Parse the id and the human class name from it.
        cwe_raw = meta.get("cwe")
        if isinstance(cwe_raw, list):
            cwe_raw = cwe_raw[0] if cwe_raw else ""
        cwe_raw = str(cwe_raw or "")
        m = re.search(r"CWE-\d{1,5}", cwe_raw, re.IGNORECASE)
        cwe = m.group(0).upper() if m else ""
        vtype = ""
        if ":" in cwe_raw:
            vtype = cwe_raw.split(":", 1)[1].strip()
        if not vtype:
            # fall back to the last meaningful segment of the rule id
            vtype = check_id.split(".")[-1].replace("-", " ").replace("_", " ").title() or "Semgrep Finding"

        return {
            "file": rel, "lineno": line, "type": vtype, "cwe": cwe or "CWE-1035",
            "severity": sev, "message": message or vtype, "check_id": check_id,
            "source": "semgrep", "confidence": 0.6,
        }
    except Exception:
        return None
