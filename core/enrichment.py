"""
CVE/CWE enrichment (Phase G)
============================

After the Wise Verdict fixes a finding's class, the TOOL ITSELF (its own HTTP
client -- NOT the LLM) looks up authoritative context for the CWE:

  * MITRE CWE  -> official name, description, potential mitigations, related
                 weaknesses.
  * NVD        -> a few real, similar CVEs for that CWE, plus an up-to-date
                 CVSS base score.

Everything is best-effort and CACHED per CWE (in-memory + on disk). Enrichment is
OPTIONAL and must NEVER break a scan: any network error / timeout / non-200 / bad
JSON is swallowed and we return whatever was gathered (possibly nothing). NVD in
particular rate-limits and returns 503 under load -- that simply means "no CVEs
this run", while the MITRE CWE context still comes through.
"""

import json
import os
import re
import tempfile

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

_UA = {"User-Agent": "LogicBreaker-AI/1.0 (security scanner; CWE/CVE enrichment)"}
_CACHE_PATH = os.environ.get("LB_ENRICH_CACHE") or \
    os.path.join(tempfile.gettempdir(), "lb_enrich_cache.json")
_cache = None


def _load_cache():
    global _cache
    if _cache is None:
        _cache = {}
        if os.path.exists(_CACHE_PATH):
            try:
                with open(_CACHE_PATH, encoding="utf-8") as fh:
                    _cache = json.load(fh)
            except Exception:
                _cache = {}
    return _cache


def _save_cache():
    try:
        with open(_CACHE_PATH, "w", encoding="utf-8") as fh:
            json.dump(_cache, fh)
    except Exception:
        pass


def enrich_cwe(cwe, timeout=8, want_cves=3):
    """Return an enrichment dict for a CWE id (or None if nothing could be
    fetched). Never raises. Cached per CWE so each weakness is fetched once."""
    if requests is None or not cwe:
        return None
    cwe = cwe.strip().upper()
    if not re.fullmatch(r"CWE-\d+", cwe):
        return None
    cache = _load_cache()
    if cwe in cache:
        return cache[cwe]

    out = {"cwe": cwe, "source": "MITRE CWE / NVD"}
    _fetch_mitre(cwe, out, timeout)
    _fetch_nvd(cwe, out, timeout, want_cves)

    # nothing useful beyond the echo keys -> treat as a miss (don't cache an
    # empty result, so a later run with the network up can succeed).
    if not (out.get("description") or out.get("similar_cves")):
        return None
    cache[cwe] = out
    _save_cache()
    return out


def _fetch_mitre(cwe, out, timeout):
    try:
        num = cwe.split("-")[1]
        r = requests.get(f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{num}",
                         headers=_UA, timeout=timeout)
        if r.status_code != 200:
            return
        w = (r.json().get("Weaknesses") or [{}])[0]
        out["name"] = w.get("Name")
        out["description"] = w.get("Description")
        ext = w.get("ExtendedDescription")
        if ext:
            out["extended_description"] = ext[:1000]
        mitigations = []
        for m in (w.get("PotentialMitigations") or []):
            txt = (m.get("Description") or "").strip()
            if txt:
                mitigations.append(txt[:300])
        if mitigations:
            out["mitigations"] = mitigations[:5]
        related = []
        for rw in (w.get("RelatedWeaknesses") or []):
            rid, nature = rw.get("CweID"), rw.get("Nature")
            if rid:
                related.append(f"CWE-{rid}" + (f" ({nature})" if nature else ""))
        if related:
            out["related_weaknesses"] = related[:8]
    except Exception:
        pass  # graceful: leave whatever we have


def _fetch_nvd(cwe, out, timeout, want_cves):
    try:
        r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                         params={"cweId": cwe, "resultsPerPage": want_cves},
                         headers=_UA, timeout=timeout)
        if r.status_code != 200:
            return  # 503/429/etc. -> no CVEs this run (degrade gracefully)
        data = r.json()
        cves, scores = [], []
        for v in (data.get("vulnerabilities") or [])[:want_cves]:
            c = v.get("cve", {})
            desc = ""
            for d in c.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            score, vector = _cvss(c)
            if score is not None:
                scores.append(score)
            cves.append({"id": c.get("id"), "summary": desc[:200],
                         "cvss": score, "vector": vector})
        if cves:
            out["similar_cves"] = cves
        if scores:
            out["cvss"] = max(scores)  # representative severity for the class
    except Exception:
        pass  # graceful: NVD is flaky; MITRE context still stands


def _cvss(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            d = arr[0].get("cvssData", {})
            return d.get("baseScore"), d.get("vectorString")
    return None, None
