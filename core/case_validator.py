"""
Case Investigator   --  Anchor-Only Verifier (no classification)
==================================================================

PHILOSOPHY:
  The AI is the SOLE classifier. It decides WHAT the vuln is (CWE, severity,
  type, family). The investigator NO LONGER looks up the CWE in a table, NO
  LONGER overrides the AI's severity, NO LONGER decides flow-vs-property.

  The investigator's ONLY job is to verify the AI's EVIDENCE:
    1. ANCHOR    -- the snippet must be in the file verbatim (>= 70% match).
    2. SINK      -- the claimed sink must be on the anchored line.
    3. SOURCE    -- for data-flow vulns, the source must be in the same function.

  That's it. No CWE lookup, no family decision, no sanitizer audit (the AI
  already did the sanitizer analysis -- the investigator does not second-guess
  it on classification, only on whether the snippet is real).

  This means: if the AI says "this is an SSRF with incomplete allowlist, HIGH
  severity, CWE-918", the investigator accepts the classification
  unconditionally IF the snippet is real and the sink is on that line. The
  investigator is a factual anchor-checker, not a classification authority.

WHY:
  The  investigator looked up the CWE in a sanitiser catalogue to decide
  flow-vs-property, then ran a regex sanitiser scan that could disagree with
  the AI. This created false negatives when the AI was right but the
  investigator's regex was wrong (e.g. on a partial SSRF allowlist, the
  investigator saw "urlparse" and cleared the flow, rejecting a real vuln).

   trusts the AI on classification. The anti-hallucination guarantee comes
  from: (a) the snippet must be real, (b) the sink must be on that line,
  (c) the AI's self-critique pass, (d) the consensus pass, (e) the execution
  prover at fix time. Five walls, no regex-based classification overrides.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip()


# Per-language function-header regexes (fallback when tree-sitter is not
# available). Used only to find the enclosing function for the source check.
_FUNCTION_HEADER_REGEXES = {
    "python":     [r"^\s*(?:async\s+)?def\s+(\w+)"],
    "javascript": [r"^\s*(?:async\s+)?function\s+(\w+)",
                   r"^\s*(?:async\s+)?(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>",
                   r"^\s*(?:async\s+)?(\w+)\s*:\s*(?:async\s*)?\([^)]*\)\s*=>",
                   r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\*?\s+(\w+)"],
    "typescript": [r"^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)",
                   r"^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\("],
    "php":        [r"^\s*(?:public|private|protected|static|\s)*\s*function\s+(\w+)"],
    "java":       [r"^\s*(?:public|private|protected|static|final|synchronized|\s)+\s*\w[\w<>\[\],\s]*\s+(\w+)\s*\("],
    "ruby":       [r"^\s*def\s+(\w+)"],
    "go":         [r"^\s*func\s+(?:\([^)]*\)\s+)?(\w+)\s*\("],
    "c_sharp":    [r"^\s*(?:public|private|protected|internal|static|virtual|override|async|\s)+\s*\w[\w<>\[\],\s]*\s+(\w+)\s*\("],
}


@dataclass
class Verdict:
    """The investigator's ruling on one case file.  only the EVIDENCE is
    checked; the classification (cwe, severity, family) is taken from the AI
    verbatim."""
    case: object
    accepted: bool
    line: int = 0
    reason: str = ""
    #  family is taken from the AI's claim, not decided by the investigator
    family: str = ""
    checks: dict = field(default_factory=dict)

    @property
    def cwe(self):
        return getattr(self.case, "cwe", "")

    @property
    def snippet(self):
        return getattr(self.case, "snippet", "")


class Investigator:
    """ anchor-only verifier. The AI is the sole classifier."""

    def __init__(self, language: str = "python"):
        self.language = language
        # tree-sitter function-boundary cache
        self._fcache = None
        self._fcache_key = None

    # ---- public API ------------------------------------------------------

    def validate(self, case, code: str) -> Verdict:
        """Verify ONE case file against `code`.  only checks the evidence
        (anchor + sink + source-in-function). Classification is taken from
        the AI verbatim."""
        lines = code.splitlines()
        checks = {}

        # Take the family from the AI's claim (default to "flow" if absent)
        family = getattr(case, "family", "") or "flow"
        checks["family"] = family

        # ---- Check 1: ANCHOR ------------------------------------------
        # The AI now ALSO returns `claimed_line` (1-based, as shown in the
        # numbered prompt). We use the AI's claim as the PRIMARY source if:
        #   (a) it's a valid 1-based line number within the code, AND
        #   (b) the snippet at that line matches the AI's snippet text.
        # Otherwise we fall back to the substring anchor search.
        claimed = int(getattr(case, "claimed_line", 0) or 0)
        line_no = 0
        if 1 <= claimed <= len(lines):
            cand = _norm(lines[claimed - 1])
            snip = _norm(case.snippet)
            # exact match OR substantial containment (same rule as _anchor)
            if cand and snip and (cand == snip or snip in cand or cand in snip):
                shorter = min(len(snip), len(cand))
                longer = max(len(snip), len(cand))
                if longer == 0 or shorter / longer >= 0.70:
                    line_no = claimed
                    checks["anchor_source"] = "ai_claimed_line"
        if not line_no:
            try:
                line_no = self._anchor(case.snippet, lines)
                checks["anchor_source"] = "substring_search"
            except Exception as e:
                checks["anchor_error"] = f"{type(e).__name__}: {e}"
                line_no = 0
        # If both methods disagree, record it (transparency, not a rejection).
        if (claimed and line_no and claimed != line_no
                and checks.get("anchor_source") == "substring_search"):
            checks["claimed_line_mismatch"] = f"AI said line {claimed}, anchor resolved to {line_no}"
        checks["anchor"] = bool(line_no)
        if not line_no:
            return Verdict(case, False, 0,
                           "snippet does not appear verbatim in the file "
                           "(invented or reformatted line)", family, checks)
        line_text = lines[line_no - 1]

        # ---- Check 2: SINK on the anchored line -----------------------
        try:
            sink_ok = self._sink_on_line(case.sink, line_text)
        except Exception as e:
            checks["sink_error"] = f"{type(e).__name__}: {e}"
            sink_ok = False
        checks["sink_on_line"] = sink_ok
        if not sink_ok:
            return Verdict(case, False, line_no,
                           f"claimed sink {case.sink!r} is not present on the "
                           f"cited line", family, checks)

        # ---- Check 3: SOURCE in the same function (flow vulns only) --
        #  respect the AI's family claim. If the AI said "property" or
        # "broken-mitigation", skip the source check entirely.
        src = (case.source or "").strip()
        if family in ("property", "broken-mitigation") or not src or src.upper() == "N/A":
            checks["source_present"] = None
            return Verdict(case, True, line_no,
                           "verified: dangerous primitive confirmed on the cited "
                           "line (property/broken-mitigation vuln)", family, checks)

        # flow vuln -- check the source is in the same function
        try:
            src_ok = self._source_is_real(case.source, code, lines, line_no)
        except Exception as e:
            checks["source_error"] = f"{type(e).__name__}: {e}"
            src_ok = False
        checks["source_present"] = src_ok
        if not src_ok:
            return Verdict(case, False, line_no,
                           f"claimed attacker source {case.source!r} is not a "
                           f"recognised untrusted input found in the same function "
                           f"as the sink", family, checks)

        return Verdict(case, True, line_no,
                       "verified: real untrusted source reaches the sink on the "
                       "cited line", family, checks)

    def validate_all(self, cases, code: str):
        return [self.validate(c, code) for c in cases]

    # ---- individual checks ----------------------------------------------

    def _anchor(self, snippet: str, lines: list) -> int:
        """ strict anchor: exact match OR substantial (>= 70%) containment."""
        target = _norm(snippet)
        if not target:
            return 0
        for i, ln in enumerate(lines, 1):
            if _norm(ln) == target:
                return i
        best = 0
        best_len = None
        for i, ln in enumerate(lines, 1):
            nl = _norm(ln)
            if not nl:
                continue
            if target in nl or nl in target:
                shorter = min(len(target), len(nl))
                longer = max(len(target), len(nl))
                if longer == 0:
                    continue
                if shorter / longer >= 0.70:
                    if best_len is None or len(nl) < best_len:
                        best, best_len = i, len(nl)
        return best

    def _sink_on_line(self, sink: str, line_text: str) -> bool:
        sink = (sink or "").strip()
        if not sink:
            return False
        core_sink = re.split(r"[(\s]", sink, 1)[0]
        nl = _norm(line_text)
        return bool(core_sink) and (core_sink in nl or _norm(sink) in nl)

    def _source_is_real(self, source: str, code: str, lines: list,
                        sink_line: int) -> bool:
        """ the source must appear in the SAME FUNCTION as the sink. The
        family decision is the AI's -- we just check the source is real and
        co-located."""
        src = (source or "").strip()
        if not src or src.upper() == "N/A":
            return False
        ncode = _norm(code)
        src_in_file = _norm(src) in ncode
        # find the enclosing function and check the source is inside it
        fn_start, fn_end = self._function_bounds(lines, sink_line)
        fn_text = "\n".join(lines[fn_start - 1:fn_end])
        src_in_function = _norm(src) in _norm(fn_text)
        return src_in_file and src_in_function

    def _function_bounds(self, lines: list, target_line: int) -> tuple:
        bounds = self._ts_function_bounds(lines, target_line)
        if bounds is not None:
            return bounds
        regexes = _FUNCTION_HEADER_REGEXES.get(self.language, [])
        start = 1
        for i in range(target_line, 0, -1):
            ln = lines[i - 1] if 1 <= i <= len(lines) else ""
            for pat in regexes:
                if re.search(pat, ln):
                    start = i
                    break
            else:
                continue
            break
        end = len(lines)
        for j in range(start + 1, len(lines) + 1):
            ln = lines[j - 1] if 1 <= j <= len(lines) else ""
            for pat in regexes:
                if re.search(pat, ln):
                    end = j - 1
                    break
            else:
                continue
            break
        return (start, end)

    def _ts_function_bounds(self, lines: list, target_line: int):
        key = hash("\n".join(lines))
        if self._fcache_key != key:
            self._fcache = self._build_ts_function_index(lines)
            self._fcache_key = key
        for (s, e) in self._fcache or []:
            if s <= target_line <= e:
                return (s, e)
        return None

    def _build_ts_function_index(self, lines: list):
        try:
            from languages.ts_loader import get_parser, available
            if not available():
                return None
            parser = get_parser(self.language)
            code = "\n".join(lines).encode("utf-8", "replace")
            tree = parser.parse(code)
            fn_node_types = {
                "python":     {"function_definition", "decorated_definition"},
                "javascript": {"function_declaration", "method_definition",
                               "arrow_function", "function_expression"},
                "typescript": {"function_declaration", "method_definition",
                               "arrow_function", "function_expression"},
                "php":        {"function_definition", "method_declaration"},
                "java":       {"method_declaration", "constructor_declaration"},
                "ruby":       {"method"},
                "go":         {"function_declaration", "method_declaration"},
                "c_sharp":    {"method_declaration", "constructor_declaration"},
            }.get(self.language, {"function_definition"})
            spans = []
            def walk(node):
                if node.type in fn_node_types:
                    if node.type == "decorated_definition":
                        for child in node.children:
                            if child.type in fn_node_types:
                                node = child
                                break
                    s = node.start_point[0] + 1
                    e = node.end_point[0] + 1
                    spans.append((s, e))
                for child in node.children:
                    walk(child)
            walk(tree.root_node)
            return spans or None
        except Exception:
            return None
