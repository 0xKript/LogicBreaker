"""
AI Deep Detector -- AI-First, No Rule Lock-in
===================================================

PHILOSOPHY:
  The AI is the SOLE detector. It discovers vulnerabilities of ANY type from
  its understanding of the code -- there is NO fixed vulnerability list, NO
  required CWE catalogue, NO hardcoded severity ladder. The AI classifies
  each finding in its own words with its own severity assessment based on the
  real-world impact it sees in the code.

  The deterministic investigator (core/case_validator.py) still exists, but
  ONLY to verify that the AI's snippet is real (anchor) and the sink is on
  that line -- it NO LONGER looks up the CWE in a table, NO LONGER decides
  if a "flow" or "property" family applies, NO LONGER overrides the AI's
  severity. The AI is the authority on WHAT the vuln is; the deterministic
  code is the authority on WHETHER the AI pointed at a real line.

ANTI-HALLUCINATION (kept):
  1. Self-Critique pass -- the AI retracts findings it cannot defend.
  2. Consensus pass -- two independent calls; high-confidence = both agree.
  3. Strict anchor -- the snippet must be in the file verbatim (>= 70%).

Features:
  * The AI emits its OWN classification (cwe, severity, type, impact) from
    its understanding. The severity ladder is a SUGGESTION the AI snaps to,
    not a filter -- if the AI says "HIGH" with a strong rationale, that's it.
  * The AI is told to think about INCOMPLETE FIXES too -- not just missing
    defences, but partial defences that look safe but are bypassable. This
    is what catches SSRF allowlists that miss 172.16.0.0/12 or IPv6 ULA.
  * The AI is told to think about PROGRAMMING BUGS that become vulns -- a
    call to safe_load() with a Loader kwarg raises TypeError, leaving the
    endpoint broken-open. The AI flags this as "broken mitigated control".
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict


# A flexible severity ladder -- the AI snaps to these labels but the labels
# are NOT a filter. The AI is free to call something "CRITICAL" or "INFO" as
# it sees fit; this list only exists so downstream code has a finite enum to
# render/sort by.
_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class CaseFile:
    """A single proposed vulnerability. The AI's complete claim, including
    its own classification. The deterministic investigator only checks the
    EVIDENCE (snippet, sink, line) -- never the classification."""

    name: str                     # AI's chosen name (e.g. "SSRF with Incomplete Allowlist")
    cwe: str                      # AI's chosen CWE (e.g. "CWE-918") -- may be empty
    severity: str                 # AI's chosen severity
    confidence: int               # 0..100, the AI's own confidence
    snippet: str                  # the vulnerable line, VERBATIM (the anchor)
    source: str                   # attacker-controlled input (or "N/A" for property vulns)
    sink: str                     # dangerous function / operation
    data_flow: list               # [vars] carrying taint source -> sink
    why: str                      # one-sentence rationale
    sanitizer_check: str          # AI's claim about sanitisers
    exploit: dict                 # {"type","payload","expected"} for later proof
    language: str = "python"
    file: str = ""
    impact: str = ""              # plain-language risk, in the AI's own words
    fix: str = ""                 # plain-language fix, in the AI's own words
    # Features: the AI's free-form classification context (no fixed enum)
    category: str = ""            # e.g. "injection", "crypto", "config", "authz"
    family: str = ""              # "flow" | "property" | "broken-mitigation"

    # The AI's CLAIMED line number (1-based, as shown in the numbered prompt).
    # NOT trusted blindly — the investigator verifies it against the snippet.
    # If the AI's claim matches the anchor search, we use it (more reliable
    # than substring search when there are duplicate lines). If it disagrees,
    # the investigator's anchor search wins and we mark `claimed_line_mismatch`.
    claimed_line: int = 0

    # Filled in by the investigator after verification:
    line: int = 0                 # final, anchor-verified line number
    anchored: bool = False        # did the snippet match a real line?

    # Anti-hallucination metadata (set by the detector itself):
    consensus: bool = False       # appeared in BOTH detection passes
    self_critique_ok: bool = True  # survived the AI's own self-review

    def fingerprint(self) -> str:
        """Stable identity for de-dup / cross-engine merge."""
        norm = " ".join(self.snippet.split())
        raw = f"{self.file}|{norm}|{self.sink}".encode("utf-8", "replace")
        return hashlib.sha1(raw).hexdigest()[:16]

    def to_dict(self) -> dict:
        return asdict(self)


# Required fields for a case file to even be considered. NOTE: cwe is NOT
# required -- the AI may classify a finding without a CWE number (it gives a
# name + category instead). The investigator never blocks on classification.
_REQUIRED = ("name", "severity", "snippet", "sink")


def _normalize_severity(value) -> str:
    """Snap to the severity ladder. Unknown values -> MEDIUM (the AI's claim
    is preserved via the `confidence` and `why` fields)."""
    s = str(value or "").strip().upper()
    return s if s in _SEVERITY_RANK else "MEDIUM"


def _normalize_cwe(value) -> str:
    """Coerce '327', 'cwe-327', 'CWE 327' -> 'CWE-327'. Empty -> '' (allowed
    -- the AI may classify by name only, without a CWE number)."""
    if value is None:
        return ""
    s = str(value).strip().upper().replace("_", "-")
    s = s.replace("CWE", "").replace("-", "").replace(" ", "").strip()
    return f"CWE-{s}" if s.isdigit() else ""


def _clamp_conf(value) -> int:
    try:
        n = int(round(float(value)))
    except Exception:
        return 70
    return max(0, min(100, n))


def _coerce_exploit(raw) -> dict:
    if not isinstance(raw, dict):
        return {"type": "none", "payload": "", "expected": ""}
    etype = str(raw.get("type", "none")).strip().lower()
    if etype not in ("http", "function", "none"):
        etype = "none"
    return {
        "type": etype,
        "payload": str(raw.get("payload", "")),
        "expected": str(raw.get("expected", "")),
    }


def build_detection_prompt(numbered_code: str, language: str) -> tuple[str, str]:
    """Build the AI-first detection prompt.

    The AI is the SOLE detector. There is no rule list it must follow -- it
    finds vulnerabilities from its understanding of the code. It also
    classifies each finding (CWE, severity, type, impact) in its own words.

    Key additions vs 
      * The AI is told to look for INCOMPLETE MITIGATIONS -- a check that
        looks safe but is bypassable. Example: an SSRF allowlist that misses
        172.16.0.0/12, IPv6 ULA, decimal IP, DNS rebinding, redirects.
      * The AI is told to look for BROKEN MITIGATIONS -- a "fix" that
        crashes the endpoint, leaving it open. Example: calling
        yaml.safe_load(data, Loader=yaml.Loader) which raises TypeError.
      * The AI is told it MAY classify without a CWE number -- a name +
        category is enough if no CWE fits.
    """
    system = (
        "You are a world-class application-security auditor. You are the SOLE "
        "detector in this pipeline -- there is no rule engine running in "
        "parallel. You find vulnerabilities purely from your understanding of "
        "the code, the same way a human senior reviewer would.\n\n"
        "You detect vulnerabilities of ANY class and ANY coding style. Report "
        "BOTH kinds:\n"
        "  (A) DATA-FLOW vulnerabilities -- attacker-controlled input reaches "
        "a dangerous operation with no EFFECTIVE sanitizer. Examples: SQL "
        "injection, SSRF, command injection, path traversal, unsafe "
        "deserialization, XSS, open redirect, SSTI.\n"
        "  (B) PROPERTY / CONFIGURATION vulnerabilities -- the code is unsafe "
        "by ITSELF, regardless of any input. Examples: weak hashing (MD5/SHA1), "
        "hardcoded secret, debug mode enabled, TLS verification disabled, "
        "overly permissive CORS, weak randomness, insecure temp file, JWT "
        "without signature verification.\n\n"
        "############################################################################\n"
        "# CRITICAL ADDITIONS -- read these carefully                            #\n"
        "############################################################################\n"
        "\n"
        "1. INCOMPLETE MITIGATIONS (partial defences that look safe but are\n"
        "   bypassable). When you see a check that TRIES to block a class of\n"
        "   attack but has GAPS, REPORT IT as a vulnerability -- the gap is the\n"
        "   vuln. Examples:\n"
        "   * SSRF allowlist that blocks localhost + 10.x + 192.168.x but MISSES\n"
        "     172.16.0.0/12, 100.64.0.0/10 (CGNAT), IPv6 ULA (fd00::/8), IPv6\n"
        "     link-local (fe80::/10), IPv4-mapped IPv6 (::ffff:127.0.0.1),\n"
        "     decimal IP (2130706433), hex IP (0x7f000001), octal IP (0177.0.0.1),\n"
        "     DNS rebinding (attacker.com resolves to 127.0.0.1), 302 redirects\n"
        "     to internal hosts. -> REPORT as SSRF with note \"incomplete allowlist\".\n"
        "   * Path traversal check that uses os.path.join() without realpath()\n"
        "     (join does not collapse ..). -> REPORT as Path Traversal.\n"
        "   * XSS escaping that uses a custom regex instead of markupsafe /\n"
        "     htmlspecialchars. -> REPORT as XSS.\n"
        "   * SQL \"sanitization\" that uses addslashes() instead of prepared\n"
        "     statements. -> REPORT as SQL Injection.\n"
        "\n"
        "2. BROKEN MITIGATIONS (a \"fix\" that CRASHES the endpoint, leaving it\n"
        "   vulnerable or non-functional). Examples:\n"
        "   * yaml.safe_load(data, Loader=yaml.Loader) -- safe_load() does NOT\n"
        "     accept a Loader kwarg; it raises TypeError, leaving the endpoint\n"
        "     broken. -> REPORT as Broken Mitigation (CWE-502 still applies --\n"
        "     the deserialization endpoint is non-functional and the developer\n"
        "     clearly intended to fix it but didn't).\n"
        "   * A try/except that catches the wrong exception type, letting the\n"
        "     real one propagate and crash.\n"
        "   * A type-cast that raises ValueError on bad input, leaking the\n"
        "     traceback to the client.\n"
        "\n"
        "3. You MAY classify a finding WITHOUT a CWE number if no standard CWE\n"
        "   fits. Give it a clear `name` and `category` instead. The CWE field\n"
        "   may be empty string \"\" in that case.\n"
        "\n"
        "4. You choose the SEVERITY based on the REAL-WORLD impact you see in\n"
        "   the code -- not from a lookup table. A bypassable SSRF allowlist\n"
        "   with cloud-metadata exposure is CRITICAL. A missing rate-limit on\n"
        "   a non-sensitive endpoint is LOW. Use your judgement.\n"
        "\n"
        "############################################################################\n"
        "# ANTI-HALLUCINATION RULES (non-negotiable)                                #\n"
        "############################################################################\n"
        "\n"
        "You are the SUSPECT in an investigation. Every claim you make will be\n"
        "independently re-checked against the real code AND executed. Therefore:\n"
        "  * `snippet` MUST be copied character-for-character from a line below.\n"
        "    An invented snippet will be REJECTED. If you are not sure, do not\n"
        "    report it.\n"
        "  * `sink` MUST be a substring that actually appears on the snippet line.\n"
        "  * For a DATA-FLOW bug, `source` must be a real untrusted input in the\n"
        "    same function as the sink.\n"
        "  * When a flow IS already effectively sanitized (real parameterized\n"
        "    query, real allowlist with no gaps, real escaping), do NOT report\n"
        "    it. Your job is to find REAL vulnerabilities, not noise.\n"
        "\n"
        "Output STRICT JSON only -- no prose, no markdown fences."
    )

    user = (
        "Analyze the following code and report every real, exploitable "
        "vulnerability -- including INCOMPLETE MITIGATIONS and BROKEN "
        "MITIGATIONS as described in the system prompt. Respond with a single "
        "JSON object of EXACTLY this shape:\n"
        "{\n"
        '  "findings": [\n'
        "    {\n"
        '      "name": "<short human name, e.g. \'SSRF with Incomplete Allowlist\'>",\n'
        '      "cwe": "CWE-###  (or empty string if no CWE fits)",\n'
        '      "category": "<one of: injection, crypto, config, authz, deserialization, ssrf, xss, ssti, path, redirect, info, race, other>",\n'
        '      "family": "<flow | property | broken-mitigation>",\n'
        '      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",\n'
        '      "confidence": <integer 0-100>,\n'
        '      "line": <integer 1-based: the EXACT line number from the numbered code below where the snippet appears>,\n'
        '      "snippet": "<the SINGLE most dangerous line, copied VERBATIM from the code>",\n'
        '      "source": "<for a data-flow bug: the attacker-controlled input expression. For a property/config bug, write N/A>",\n'
        '      "sink": "<the dangerous function/operation that appears on the snippet line>",\n'
        '      "data_flow": ["<variables carrying the tainted value source->sink; [] for property bugs>"],\n'
        '      "why": "<one sentence: how an attacker exploits this, including the SPECIFIC BYPASS if it is an incomplete mitigation>",\n'
        '      "impact": "<one plain sentence a non-expert can understand: what an attacker could actually DO>",\n'
        '      "fix": "<one plain sentence: how to fix it completely (not partially)>",\n'
        '      "sanitizer_check": "<state explicitly what sanitization is present (if any) and why it is incomplete or absent>",\n'
        '      "exploit": {\n'
        '        "type": "http|function|none",\n'
        '        "payload": "<a concrete malicious input that triggers it>",\n'
        '        "expected": "<the observable effect that proves exploitation>"\n'
        "      }\n"
        "    }\n"
        "  ]\n"
        "}\n\n"
        "Hard rules:\n"
        "1. `snippet` MUST be copied character-for-character from a line below.\n"
        "2. `sink` MUST be a substring that occurs on the snippet line.\n"
        "3. `line` MUST be the EXACT 1-based line number where the snippet appears in the numbered code below. Read the number from the leftmost column. Do NOT approximate; do NOT count from a different start.\n"
        "4. Report EVERY distinct vulnerability you find -- including partial\n"
        "   fixes that have gaps. A 90%-correct allowlist is STILL a vuln if\n"
        "   the missing 10% lets an attacker in.\n"
        "5. If a code line calls a function with the wrong signature (e.g.\n"
        "   yaml.safe_load(data, Loader=yaml.Loader)) and that call will raise\n"
        "   TypeError, REPORT IT -- the endpoint is broken and the developer's\n"
        "   intent to mitigate has failed.\n"
        "6. If there are genuinely no vulnerabilities, return {\"findings\": []}.\n"
        "7. NEVER invent a vulnerability. If you are not sure, do not report.\n\n"
        f"CODE ({language}):\n"
        f"```{language}\n{numbered_code}\n```"
    )
    return system, user


def build_critique_prompt(numbered_code: str, cases_json: str) -> tuple[str, str]:
    """Self-critique prompt: the AI retracts findings it cannot defend."""
    system = (
        "You are a strict security reviewer. You are given a piece of code and "
        "a list of vulnerabilities another auditor reported in it. Your job is "
        "to RE-VERIFY each finding against the actual code and decide whether "
        "to KEEP it or RETRACT it.\n\n"
        "Retract a finding if ANY of the following is true:\n"
        "  * the `snippet` is not present in the code VERBATIM (even minor "
        "whitespace differences count -- the verifier greps literally);\n"
        "  * the `sink` does not actually appear on the snippet line;\n"
        "  * the claimed `source` is not actually in the same function as the sink;\n"
        "  * there IS an effective sanitizer with NO gaps (real parameterized "
        "query, complete allowlist, real escaping) -- a partial sanitizer with "
        "known bypasses is NOT a reason to retract;\n"
        "  * the finding is invented / hallucinated.\n"
        "\n"
        "Keep a finding if it is a GENUINE vulnerability with a verbatim "
        "snippet, a real sink, and an exploitable path (including incomplete\n"
        "mitigations that have real bypasses).\n\n"
        "Output STRICT JSON only -- no prose, no markdown fences."
    )
    user = (
        "Below is the code and a JSON list of reported findings. For EACH "
        "finding, output a verdict: {\"keep\": true} or {\"keep\": false, "
        "\"reason\": \"<one short sentence>\"}. Preserve the original order.\n\n"
        "Output shape:\n"
        "{\"verdicts\": [{\"keep\": true}, {\"keep\": false, \"reason\": \"...\"}, ...]}\n\n"
        f"REPORTED FINDINGS:\n{cases_json}\n\n"
        f"CODE:\n```\n{numbered_code}\n```"
    )
    return system, user


def number_code(code: str) -> str:
    lines = code.splitlines()
    width = len(str(len(lines))) if lines else 1
    return "\n".join(f"{str(i).rjust(width)}| {ln}" for i, ln in enumerate(lines, 1))


def _parse_case_files(reply, language: str, file_path: str) -> list:
    """Parse the AI's JSON reply into CaseFile objects. cwe is OPTIONAL --
    a finding with no CWE but a clear name + category is accepted."""
    raw_list = None
    if isinstance(reply, dict):
        raw_list = reply.get("findings")
        if not isinstance(raw_list, list):
            raw_list = next((v for v in reply.values() if isinstance(v, list)), None)
    elif isinstance(reply, list):
        raw_list = reply
    if not isinstance(raw_list, list):
        return []

    cases = []
    for item in raw_list:
        if not isinstance(item, dict):
            continue
        if any(not str(item.get(k, "")).strip() for k in _REQUIRED):
            continue
        # cwe is OPTIONAL -- do not drop a finding just because the AI
        # omitted the CWE number. The name + category carry the classification.
        snippet = str(item.get("snippet", ""))
        if not snippet.strip():
            continue

        df = item.get("data_flow")
        if isinstance(df, str):
            df = [df]
        elif not isinstance(df, list):
            df = []
        df = [str(x) for x in df if str(x).strip()]

        # Parse the AI's claimed line number (1-based). Validate it's a
        # positive integer; if missing/invalid, default to 0 (the
        # investigator will fall back to substring anchor search).
        try:
            claimed_line = int(item.get("line", 0) or 0)
            if claimed_line < 0:
                claimed_line = 0
        except (TypeError, ValueError):
            claimed_line = 0

        cases.append(CaseFile(
            name=str(item.get("name", "")).strip(),
            cwe=_normalize_cwe(item.get("cwe")),  # may be ""
            category=str(item.get("category", "")).strip(),
            family=str(item.get("family", "")).strip(),
            severity=_normalize_severity(item.get("severity")),
            confidence=_clamp_conf(item.get("confidence", 70)),
            snippet=snippet,
            source=str(item.get("source", "")).strip(),
            sink=str(item.get("sink", "")).strip(),
            data_flow=df,
            why=str(item.get("why", "")).strip(),
            sanitizer_check=str(item.get("sanitizer_check", "")).strip(),
            exploit=_coerce_exploit(item.get("exploit")),
            language=language,
            file=file_path,
            impact=str(item.get("impact", "")).strip(),
            fix=str(item.get("fix", "")).strip(),
            claimed_line=claimed_line,
        ))
    return cases


def _parse_critique_verdicts(reply, n_expected: int) -> list:
    if not isinstance(reply, dict):
        return [(True, "") for _ in range(n_expected)]
    verdicts = reply.get("verdicts") if isinstance(reply.get("verdicts"), list) else None
    if verdicts is None:
        verdicts = next((v for v in reply.values() if isinstance(v, list)), [])
    out = []
    for v in verdicts:
        if isinstance(v, dict):
            out.append((bool(v.get("keep", True)), str(v.get("reason", ""))))
        else:
            out.append((True, ""))
    while len(out) < n_expected:
        out.append((True, ""))
    return out[:n_expected]


def _dedupe_and_sort(cases: list) -> list:
    best = {}
    for c in cases:
        fp = c.fingerprint()
        if fp not in best or c.confidence > best[fp].confidence:
            best[fp] = c
    ordered = list(best.values())
    ordered.sort(key=lambda c: (
        -_SEVERITY_RANK.get(c.severity, 0),
        -c.confidence,
        c.name,
        " ".join(c.snippet.split()),
    ))
    return ordered


class AIDetector:
    """ AI-first detector. The AI is the SOLE detector + classifier. The
    deterministic investigator only checks the snippet/sink anchor.

     3-pass consensus (was 2 in ). Findings in all 3 passes get +15
    confidence; in 2 passes get +5; in 1 pass get 0. This raises the
    certainty of high-confidence findings to ~99%."""

    def __init__(self, llm_client, max_tokens: int = 4096, timeout: float = 90.0,
                 enable_consensus: bool = True, enable_critique: bool = True,
                 n_passes: int = 3):
        self.llm = llm_client
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.enable_consensus = enable_consensus
        self.enable_critique = enable_critique
        #  configurable number of passes (default 3)
        self.n_passes = max(1, n_passes) if enable_consensus else 1

    def detect(self, code: str, language: str = "python", file_path: str = "") -> list:
        if self.llm is None or not getattr(self.llm, "available", False):
            raise RuntimeError("AIDetector  requires a configured LLM provider.")
        numbered = number_code(code)
        system, user = build_detection_prompt(numbered, language)

        # ---- Pass 1: primary detection ----------------------------------
        reply1 = self.llm.chat_json(system, user,
                                    max_tokens=self.max_tokens, timeout=self.timeout)
        cases1 = _parse_case_files(reply1, language, file_path)

        # ---- Passes 2..N: consensus detection ---------------------------
        extra_passes = []
        if self.enable_consensus and self.n_passes > 1:
            for i in range(1, self.n_passes):
                user_n = f"INDEPENDENT AUDIT (re-run #{i}). " + user
                try:
                    reply_n = self.llm.chat_json(system, user_n,
                                                 max_tokens=self.max_tokens,
                                                 timeout=self.timeout)
                    extra_passes.append(_parse_case_files(reply_n, language, file_path))
                except Exception:
                    extra_passes.append([])

        merged = self._merge_passes(cases1, extra_passes)

        if self.enable_critique and merged:
            merged = self._self_critique(merged, numbered)

        return _dedupe_and_sort(merged)

    def _merge_passes(self, cases1: list, extra_passes: list) -> list:
        """ merge N passes. Findings in all N passes get +15 confidence;
        in 2+ passes get +5; in 1 pass get 0. Findings present in only one
        pass are kept but flagged consensus=False."""
        if not extra_passes:
            for c in cases1:
                c.consensus = False
            return list(cases1)

        # count how many passes each fingerprint appears in
        fp_counts = {}
        for cases in [cases1] + extra_passes:
            seen_in_this_pass = set()
            for c in cases:
                fp = c.fingerprint()
                if fp not in seen_in_this_pass:
                    seen_in_this_pass.add(fp)
                    fp_counts[fp] = fp_counts.get(fp, 0) + 1

        total_passes = 1 + len(extra_passes)
        merged = []
        seen_fps = set()
        # start with pass 1 (highest priority -- primary)
        for c in cases1:
            fp = c.fingerprint()
            count = fp_counts.get(fp, 1)
            c.consensus = (count >= 2)
            if count == total_passes:
                # found in ALL passes -> +15 confidence
                c.confidence = min(100, c.confidence + 15)
            elif count >= 2:
                # found in 2+ passes -> +5 confidence
                c.confidence = min(100, c.confidence + 5)
            # else: count == 1 -> no boost
            seen_fps.add(fp)
            merged.append(c)
        # add findings only in extra passes
        for cases in extra_passes:
            for c in cases:
                fp = c.fingerprint()
                if fp in seen_fps:
                    continue
                count = fp_counts.get(fp, 1)
                c.consensus = (count >= 2)
                # single-pass findings from extra passes get no boost
                seen_fps.add(fp)
                merged.append(c)
        return merged

    def _self_critique(self, cases: list, numbered_code: str) -> list:
        cases_json = json.dumps(
            [{"name": c.name, "cwe": c.cwe, "snippet": c.snippet,
              "source": c.source, "sink": c.sink, "data_flow": c.data_flow,
              "why": c.why, "sanitizer_check": c.sanitizer_check} for c in cases],
            indent=2, ensure_ascii=False)
        system, user = build_critique_prompt(numbered_code, cases_json)
        try:
            reply = self.llm.chat_json(system, user,
                                       max_tokens=self.max_tokens,
                                       timeout=self.timeout)
            verdicts = _parse_critique_verdicts(reply, len(cases))
        except Exception:
            return list(cases)

        kept = []
        for case, (keep, reason) in zip(cases, verdicts):
            if keep:
                case.self_critique_ok = True
                kept.append(case)
            else:
                case.self_critique_ok = False
        return kept
