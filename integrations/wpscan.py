"""
WPScan integration (Phase H) -- LIVE WordPress sites (URLs only)
================================================================

A SEPARATE mode from code scanning. The engine + Semgrep + LLM analyse source
FILES on disk; WPScan analyses a RUNNING WordPress site over HTTP -- fingerprints
the core version, enumerates plugins/themes, and reports their KNOWN CVEs from the
WPScan vulnerability database.

We shell out to the external `wpscan` tool (JSON output), normalise its result
into the unified Finding shape, and let the standard reporters render it. WPScan
is OPTIONAL: if it isn't installed we return a sentinel so the caller prints a
clear warning instead of crashing. The vuln database needs an API token, taken
from --wpscan-token or the WPSCAN_API_TOKEN env var (never hardcoded).
"""

import json
import os
import re
import shutil
import subprocess


def is_available():
    """True if the `wpscan` binary is on PATH."""
    return shutil.which("wpscan") is not None


def run_wpscan(url, api_token=None, timeout=900):
    """Run wpscan against a live URL and return a list of normalised finding
    dicts. Returns None if wpscan is NOT installed (caller warns + stops this
    mode). Returns [] on any error. Never raises."""
    if not is_available():
        return None
    token = api_token or os.environ.get("WPSCAN_API_TOKEN")
    cmd = ["wpscan", "--url", url, "--format", "json", "--no-banner",
           "--random-user-agent"]
    if token:
        cmd += ["--api-token", token]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return []
    raw = proc.stdout or ""
    if not raw.strip():
        return []
    data = _parse_json(raw)
    if data is None:
        return []
    return _normalize(data, url)


def _parse_json(raw):
    try:
        return json.loads(raw)
    except Exception:
        # wpscan can emit progress noise before the JSON; grab the JSON object.
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if not m:
            return None
        try:
            return json.loads(m.group(0))
        except Exception:
            return None


def _normalize(data, url):
    """Map a wpscan JSON report to the unified finding shape: WordPress core,
    plugin and theme vulnerabilities (each with its CVEs and fix version)."""
    out = []

    ver = data.get("version") or {}
    core_num = ver.get("number", "")
    for v in (ver.get("vulnerabilities") or []):
        out.append(_vuln(v, component=f"WordPress core {core_num}".strip(),
                         kind="core", url=url))

    for name, p in (data.get("plugins") or {}).items():
        pver = _component_version(p)
        for v in (p.get("vulnerabilities") or []):
            out.append(_vuln(v, component=f"plugin: {name} {pver}".strip(),
                             kind="plugin", url=url))

    for name, t in (data.get("themes") or {}).items():
        tver = _component_version(t)
        for v in (t.get("vulnerabilities") or []):
            out.append(_vuln(v, component=f"theme: {name} {tver}".strip(),
                             kind="theme", url=url))
    return out


def _component_version(comp):
    ver = comp.get("version")
    if isinstance(ver, dict):
        return ver.get("number", "") or ""
    return ver or ""


def _vuln(v, component, kind, url):
    refs = v.get("references") or {}
    cves = ["CVE-" + str(c) if not str(c).upper().startswith("CVE-") else str(c)
            for c in (refs.get("cve") or [])]
    return {
        "title": v.get("title") or "Known vulnerability",
        "component": component,
        "kind": kind,
        "cves": cves,
        "fixed_in": v.get("fixed_in"),
        "references": [u for u in (refs.get("url") or [])][:5],
        "wpvulndb": refs.get("wpvulndb") or [],
        "url": url,
    }
