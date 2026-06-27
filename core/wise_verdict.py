"""
Wise Verdict (Phase F) -- the judge (section 7 of the brief)
============================================================

A single DECISIVE ruling per candidate finding, reached by WEIGHING the evidence
of three sources -- NOT by counting votes:

  * 🔧 Engine   -- a real source→sink, with the engine's sanitiser analysis
                   already applied (a taint finding is emitted only when the
                   class-appropriate sanitiser was absent / ineffective).
  * 🟢 Semgrep  -- a rule matched on the real code.
  * 🧠 LLM      -- a contextual / effectiveness judgment plus FORCED evidence
                   {line, source, sink, sanitizer_present}. The LLM corrects the
                   engine's label (Phase C) and can rule a finding safe.

Rules enforced (section 7):
  1. CONFIRMED when the weighed evidence supports a real, reachable, effectively-
     UNSANITISED source→sink.
  2. DROPPED silently when a sanitiser is present AND judged effective (the LLM
     ruled it safe WITH evidence), or when there is no real source→sink (an
     LLM-discovered finding whose cited source/sink is absent from the code).
  3. No "needs review" / "medium confidence" limbo -- confirmed or dropped.
  4. Every ruling carries a one-line reason + a confidence number (for sorting).
  5. Detection is a UNION: anything engine OR Semgrep OR LLM raised is judged;
     a candidate is discarded ONLY when the weighed verdict fails on actual code.
  6. Determinism: rulings are cached by hash(code)+model (in-memory + optional on
     disk) so the same code yields the same ruling on re-runs.
"""

import hashlib
import json
import os
import re


def _tokens(s):
    """Word tokens (len>=3), lower-cased, for grounding checks."""
    return {t.lower() for t in re.findall(r"[A-Za-z_]\w{2,}", s or "")}


# Ubiquitous words that appear in almost any program and therefore prove NOTHING
# about grounding: an LLM can "cite" them for an invented bug and they will always
# match. They are excluded from the distinctive-token check (FIX B2).
_STOP = {
    "request", "req", "response", "resp", "res", "data", "file", "files",
    "user", "users", "query", "input", "name", "names", "value", "values",
    "val", "result", "results", "id", "ids", "path", "paths", "url", "urls",
    "uri", "get", "post", "put", "patch", "head", "the", "and", "for", "with",
    "this", "self", "that", "return", "def", "var", "let", "const", "function",
    "func", "true", "false", "none", "null", "nil", "from", "import", "json",
    "str", "string", "int", "num", "bool", "dict", "list", "obj", "object",
    "key", "item", "items", "type", "text", "body", "form", "field", "line",
    "code", "msg", "message", "out", "tmp", "buf",
}


def _distinctive(s):
    """Tokens of `s` minus the ubiquitous stop-list -- the words that actually
    pin an evidence claim to specific code (FIX B2)."""
    return _tokens(s) - _STOP


class WiseVerdict:
    def __init__(self, model="engine-only", cache_path=None):
        self.model = model or "engine-only"
        self.cache_path = cache_path
        self.cache = {}
        if cache_path and os.path.exists(cache_path):
            try:
                with open(cache_path, encoding="utf-8") as fh:
                    self.cache = json.load(fh)
            except Exception:
                self.cache = {}

    # -- public ----------------------------------------------------------
    def judge_all(self, findings):
        """Judge every candidate; return ONLY the confirmed findings (dropped
        ones are removed silently). Each kept finding gets
        f.verdict = {ruling, reason, confidence, sources}."""
        kept = []
        for f in findings:
            ruling = self._cached_judge(f)
            f.verdict = ruling
            if ruling["ruling"] == "confirmed":
                # a live dynamic proof outranks everything; otherwise this is a
                # verdict-confirmed finding.
                if getattr(f, "status", "") != "CONFIRMED":
                    f.status = "CONFIRMED"
                f.confidence = ruling["confidence"]
                kept.append(f)
        self._save()
        return kept

    # -- determinism cache ----------------------------------------------
    def _evidence_sig(self, f):
        """Signature of the ENGINE SIGNAL only -- matcher id, detection method,
        type and status. Deliberately EXCLUDES the free-text LLM `evidence` string
        (which could drift run-to-run): with temperature 0 + a persistent LLM cache
        the engine signal is stable, so the same code + same model must always
        yield the same ruling. Determinism (section 7, rule 6)."""
        return "|".join([
            f.matcher_id or "",
            f.detection_method or "",
            f.type or "",
            getattr(f, "status", "") or "",
        ])

    def _cached_judge(self, f):
        key = hashlib.sha256(
            ((f.source or "") + "\x00" + self.model + "\x00" + self._evidence_sig(f)).encode()
        ).hexdigest()
        if key in self.cache:
            return self.cache[key]
        ruling = self._weigh(f)
        self.cache[key] = ruling
        return ruling

    # -- the weighing ----------------------------------------------------
    def _weigh(self, f):
        dm = (f.detection_method or "").lower()
        mid = (f.matcher_id or "").lower()
        is_semgrep = (mid == "semgrep") or ("semgrep" in dm)
        is_llm_net = (mid == "llm-safety-net")
        is_engine = not is_semgrep and not is_llm_net
        engine_flow = "taint" in dm
        llm_touched = ("llm" in dm) or (f.evidence is not None)
        llm_refuted = getattr(f, "status", "") == "LIKELY_FALSE_POSITIVE"

        # RULE 2a -- effective sanitiser / not reachable: the LLM ruled it safe
        # WITH evidence (Phase C). Turn that limbo into a decisive DROP.
        if llm_refuted:
            return self._drop("sanitizer judged effective / not reachable by the LLM "
                              "on the real code")

        # RULE 2b -- hallucination: an LLM-DISCOVERED finding whose cited source
        # AND sink are both absent from the actual code fails verification.
        if is_llm_net:
            if not self._grounded(f.evidence, f.source):
                return self._drop("LLM-cited source/sink not present in the code "
                                  "(hallucination)")
            return self._confirm("LLM safety-net caught a bug the engine and Semgrep "
                                 "missed; evidence verified against the code", f, ["llm"])

        # RULE 1 + 5 -- engine and/or Semgrep raised a real, reachable issue (the
        # engine already cleared class-appropriate sanitisers before emitting). If
        # the LLM also spoke (with evidence) it corroborated/classified. CONFIRM.
        sources = []
        if is_engine:
            sources.append("engine")
        if is_semgrep:
            sources.append("semgrep")
        if llm_touched and f.evidence:
            sources.append("llm")
        if engine_flow:
            why = "engine traced untrusted input to the sink with no effective sanitizer"
        elif is_engine:
            why = "engine flagged a real, reachable issue"
        else:
            why = "Semgrep rule matched on the real code"
        if "semgrep" in sources and "engine" in sources:
            why += "; Semgrep corroborates"
        if "llm" in sources:
            why += "; LLM confirmed/classified"
        return self._confirm(why, f, sources)

    def _grounded(self, evidence, code):
        """STRICT grounding for an LLM-DISCOVERED finding (FIX B2). An invented
        finding must be impossible to confirm; a real one the LLM points at (real
        line + real sink + real source) is confirmed. ALL must hold:

          1. the cited evidence.line exists in the unit AND that line (or its ±1
             neighbours) actually contains the cited sink token;
          2. BOTH a DISTINCTIVE source token AND a DISTINCTIVE sink token (after
             removing ubiquitous stop-words) appear in the code -- not just one;
          3. at least 2 distinctive tokens overall are present.

        Deterministic: pure set / line logic, no sampling."""
        ev = evidence or {}
        code = code or ""
        lines = code.split("\n")
        n = len(lines)
        code_tok = _tokens(code)

        # (2) a distinctive source token AND a distinctive sink token, both present
        src_dist = _distinctive(ev.get("source", ""))
        sink_dist = _distinctive(ev.get("sink", ""))
        src_hit = src_dist & code_tok
        sink_hit = sink_dist & code_tok
        if not src_hit or not sink_hit:
            return False
        # (3) >= 2 distinctive tokens total across source + sink
        if len(src_hit | sink_hit) < 2:
            return False

        # (1) the cited line must EXIST in the unit and (±1) carry the sink token.
        # The LLM is shown only the function body, so evidence.line is 1-based
        # within that snippet.
        try:
            cited = int(ev.get("line") or 0)
        except (TypeError, ValueError):
            return False
        if cited < 1 or cited > n:
            return False
        window_tok = _tokens(" ".join(lines[max(0, cited - 2):min(n, cited + 1)]))
        if not (sink_dist & window_tok):
            return False
        return True

    def _confirm(self, reason, f, sources):
        base = float(getattr(f, "confidence", 0.5) or 0.5)
        # corroboration nudges confidence up (for SORTING only, never hedging).
        conf = min(0.99, round(base + 0.04 * max(0, len(set(sources)) - 1), 2))
        return {"ruling": "confirmed", "reason": reason, "confidence": conf,
                "sources": sorted(set(sources))}

    def _drop(self, reason):
        return {"ruling": "dropped", "reason": reason, "confidence": 0.0, "sources": []}

    def _save(self):
        if not self.cache_path:
            return
        try:
            d = os.path.dirname(self.cache_path)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(self.cache_path, "w", encoding="utf-8") as fh:
                json.dump(self.cache, fh)
        except Exception:
            pass
