"""
Scan engine
===========

The language-agnostic core. Given a target directory:

  1. Recursively scan for analysable source files (any of 40+ languages).
  2. Parse each file with tree-sitter and extract function/method units.
  3. Extract HTTP routes (multi-framework).
  4. Run every registered matcher over every unit.
  5. Optionally run LLM triage to (a) reduce false positives and (b) add
     coverage for languages/patterns the heuristics don't deeply model.

Returns a structured result the orchestrator turns into findings, dynamic
tests, patches, and reports.
"""

import concurrent.futures
import hashlib
import os
import re
import tempfile

from languages import ts_parser
from languages.registry import is_deep, display_name
from matchers.base import ScanContext
from matchers.registry import load_matchers
from scanners.file_scanner import scan_tree
from scanners.route_extractor import extract_routes_from_unit, extract_routes_from_text


def _module_level_source(text, units):
    """Return the file's top-level code: all lines that fall OUTSIDE every
    extracted function/method body. This captures module-level statements
    (framework debug flags, global config, etc.) that matchers would otherwise
    never see."""
    lines = text.split("\n")
    n = len(lines)
    inside = [False] * (n + 2)
    for u in units:
        start = u.get("lineno")
        if not start:
            continue
        body = u.get("source", "")
        span = body.count("\n") + 1
        for ln in range(start, min(start + span, n + 1)):
            if 1 <= ln <= n:
                inside[ln] = True
    kept = [lines[i - 1] for i in range(1, n + 1) if not inside[i]]
    return "\n".join(kept)


def _cwe_ok(cwe):
    """True if `cwe` looks like a real CWE id (CWE-<digits>). Guards against the
    LLM returning junk in the correct_cwe field before we overwrite a finding."""
    return bool(re.fullmatch(r"CWE-\d{1,5}", (cwe or "").strip(), re.IGNORECASE))


class ScanEngine:
    def __init__(self, target_dir, llm=None, enabled_matchers=None,
                 max_file_bytes=1_500_000, max_files=None, use_semgrep=False,
                 enable_taint=True):
        self.target_dir = target_dir
        self.llm = llm
        self.matchers = load_matchers(enabled_matchers)
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files
        # Phase D: run Semgrep alongside the engine and merge. OFF by default so
        # the deterministic engine path (and the benchmark) is never perturbed;
        # the orchestrator / CLI turns it on for real scans.
        self.use_semgrep = use_semgrep
        # TAINT ENGINE CONTROL: when False, the taint engine is skipped entirely.
        # mode=ai uses the AI for data-flow analysis instead, so it sets this to
        # False. Default True so the engine-only benchmark path and fast/hybrid
        # modes keep full taint analysis.
        self.enable_taint = enable_taint
        # Phase F (rule 6): cache LLM JSON responses by hash(prompt)+model so a
        # re-scan of unchanged code is never re-billed (in-memory always; on disk
        # when LB_LLM_CACHE points at a file).
        self._llm_cache = {}
        # DETERMINISM: persist the LLM-response cache by DEFAULT (not only when
        # LB_LLM_CACHE is set). Identical prompts then return the cached response
        # across separate `python main.py` runs, so the same code yields the same
        # findings every time. LB_LLM_CACHE overrides the path. The cache is only
        # loaded when an LLM is configured, so the engine-only benchmark path
        # (llm=None) is never touched.
        self.llm_cache_path = os.environ.get("LB_LLM_CACHE") or \
            os.path.join(tempfile.gettempdir(), "lb_llm_cache.json")
        if self.llm and os.path.exists(self.llm_cache_path):
            try:
                import json as _json
                with open(self.llm_cache_path, encoding="utf-8") as fh:
                    self._llm_cache = _json.load(fh)
            except Exception:
                self._llm_cache = {}

    def _llm_chat_json(self, system, user):
        """LLM JSON call wrapped in a determinism/cost cache keyed by
        hash(system+user)+model. Identical code is never re-billed on a re-run."""
        model = getattr(self.llm, "model", "") or ""
        key = hashlib.sha256((model + "\x00" + system + "\x00" + user).encode()).hexdigest()
        if key in self._llm_cache:
            return self._llm_cache[key]
        try:
            resp = self.llm.chat_json(system, user)
        except ValueError:
            # DETERMINISM (FIX A): a parse failure is a property of (code, model),
            # not luck. Cache an explicit empty verdict so EVERY re-run reproduces
            # it, instead of one run skipping (engine defaults) and the next
            # parsing cleanly and relabelling -- the run-to-run drift we are fixing.
            resp = None
        except Exception:
            # transient (network / timeout / HTTP error): do NOT poison the cache;
            # skip triage for this finding on THIS run and let a later run retry.
            return None
        self._llm_cache[key] = resp
        if self.llm_cache_path:
            try:
                import json as _json
                with open(self.llm_cache_path, "w", encoding="utf-8") as fh:
                    _json.dump(self._llm_cache, fh)
            except Exception:
                pass
        return resp

    # ------------------------------------------------------------------
    def scan(self, progress_cb=None):
        files, stats = scan_tree(self.target_dir, self.max_file_bytes, self.max_files)

        all_units = []
        routes = []
        parse_errors = 0
        # collect (rel_path, language, source_bytes, units) for the taint engine
        taint_inputs = []
        # whole-file source per rel_path, for context-aware (browser-vs-server) FP filtering
        self._file_text = {}

        for i, finfo in enumerate(files):
            if progress_cb:
                progress_cb(i + 1, len(files), finfo["rel_path"])
            try:
                with open(finfo["path"], "rb") as fh:
                    source_bytes = fh.read()
            except OSError:
                continue

            language = finfo["language"]
            try:
                self._file_text[finfo["rel_path"]] = source_bytes.decode("utf-8", errors="replace")
            except Exception:
                self._file_text[finfo["rel_path"]] = ""
            try:
                units = ts_parser.extract_functions(language, source_bytes, finfo["rel_path"])
            except Exception:
                parse_errors += 1
                units = []

            # collect files in any taint-supported language for the taint engine
            from core.taint_engine import LANG_FUNC_NODES as _TAINT_LANGS
            if language in _TAINT_LANGS:
                taint_inputs.append((finfo["rel_path"], language, source_bytes, units))

            for u in units:
                u["deep"] = is_deep(language)
                # routes attached to this unit
                u_routes = extract_routes_from_unit(u)
                for r in u_routes:
                    routes.append({**r, "handler": u["qualname"], "file": u["file"],
                                   "language": language})
            all_units.extend(units)

            # Synthetic MODULE unit: lines that are NOT inside any extracted
            # function (top-level statements such as a framework's debug flag,
            # global config, route registrations). Without this, module-level
            # issues are invisible to matchers that only see function bodies.
            try:
                text = source_bytes.decode("utf-8", errors="replace")
                module_src = _module_level_source(text, units)
                if module_src.strip():
                    all_units.append({
                        "name": "<module>", "qualname": "<module>",
                        "source": module_src, "language": language,
                        "file": finfo["rel_path"], "lineno": 1,
                        "params": [], "deep": is_deep(language),
                        "is_module": True,
                    })
            except Exception:
                pass

            # file-level route scan (catches routes defined outside functions)
            try:
                text = source_bytes.decode("utf-8", errors="replace")
                for r in extract_routes_from_text(text, finfo["rel_path"]):
                    routes.append(r)
            except Exception:
                pass

        # dedupe routes
        seen = set()
        deduped_routes = []
        for r in routes:
            key = (tuple(r.get("methods", [])), r.get("path"), r.get("file"))
            if key not in seen:
                seen.add(key)
                deduped_routes.append(r)

        # Link routes to their handler functions by line proximity. A route
        # decorator (e.g. @app.route("/user/<user_id>")) sits a few lines above
        # the function it decorates; tag that unit as a request handler and copy
        # the route's path-params onto it. This makes handler-aware matchers
        # (IDOR, broken-auth, missing-auth, rate-limit) fire on decorated
        # handlers even though the decorator is not part of the unit body.
        units_by_file = {}
        for u in all_units:
            units_by_file.setdefault(u.get("file"), []).append(u)
        for r in deduped_routes:
            rfile = r.get("file")
            rline = r.get("lineno") or r.get("line")
            cands = units_by_file.get(rfile, [])
            target = None
            if rline is not None:
                # the handler is the first unit starting on/after the route line
                after = [u for u in cands if (u.get("lineno") or 0) >= rline]
                if after:
                    target = min(after, key=lambda u: u.get("lineno") or 0)
            if target is None and r.get("handler"):
                target = next((u for u in cands if u.get("qualname") == r["handler"]), None)
            if target is None and len(cands) == 1:
                target = cands[0]
            if target is not None:
                target["is_route_handler"] = True
                target.setdefault("route_paths", []).append(r.get("path", ""))
                if not r.get("handler"):
                    r["handler"] = target.get("qualname")

        context = ScanContext(target_dir=self.target_dir, all_units=all_units,
                              routes=deduped_routes, llm=self.llm)

        findings = self._run_matchers(all_units, context)

        # ---- Taint engine (Python): data-flow + taint + interprocedural +
        # cross-file. Runs ALONGSIDE the regex matchers and is merged with
        # deduplication so we never double-report the same (type, file, line).
        # Taint findings catch cross-function / cross-file flows the per-function
        # matchers miss, and carry higher confidence (a real source->sink path).
        try:
            findings = self._merge_taint_findings(findings, taint_inputs)
        except Exception:
            pass  # the taint engine must never break a scan; matchers stand alone

        # ---- Semgrep (Phase D): complementary rule-based detection, run in a
        # subprocess and merged + de-duplicated against engine findings. Gated by
        # use_semgrep so the engine-only path stays deterministic. Never crashes
        # the scan: if semgrep is missing it warns once and continues.
        if self.use_semgrep:
            try:
                findings = self._merge_semgrep_findings(findings)
            except Exception:
                pass  # the optional Semgrep layer must never break a scan

        # ---- Severity brain: re-score every finding's severity from CONTEXT
        # (CVSS 1, driven by the VKB) instead of a static per-type constant.
        # This runs AFTER all detection + merge, changes only severity/CVSS/
        # confidence fields, and never alters the SET of findings -- so detection
        # accuracy (precision/recall) is provably unchanged.
        try:
            from core.severity_engine import apply_severity
            apply_severity(findings, self.target_dir)
        except Exception:
            pass  # severity scoring must never break a scan

        stats["functions"] = len(all_units)
        stats["routes"] = len(deduped_routes)
        stats["parse_errors"] = parse_errors

        return {
            "stats": stats,
            "units": all_units,
            "routes": deduped_routes,
            "findings": findings,
            "files": files,
        }

    # ------------------------------------------------------------------
    def _merge_taint_findings(self, findings, taint_inputs):
        """Run the taint engine over all Python files (intra-function, then
        interprocedural + cross-file) and merge its findings into `findings`,
        deduplicating on (type, file, function) and on nearby lines so we never
        double-report what a regex matcher already found. Taint findings that ARE
        new (cross-function / cross-file flows) are added; where a taint finding
        overlaps an existing one, we keep the existing one but upgrade its
        confidence and detection method (a real source->sink path is stronger
        evidence than a text pattern)."""
        # MODE CONTROL: when enable_taint is False (mode=ai), the taint engine
        # is skipped entirely -- the AI detector does the data-flow analysis.
        if not getattr(self, "enable_taint", True):
            return findings
        from core import taint_engine as TE
        from matchers.base import Finding

        if not taint_inputs:
            return findings

        taint_findings = []
        # Build the interprocedural analyzer first so we have the global
        # return-taint map (which functions return tainted data). This lets the
        # per-file analysis avoid false positives from helpers that sanitise
        # internally (e.g. x = safe_build(tainted) where safe_build is clean).
        ia = TE.InterproceduralAnalyzer()
        for rel_path, language, source_bytes, units in taint_inputs:
            ia.add_file(language, source_bytes, rel_path, units)
        ia.build_summaries()
        rt_map = getattr(ia, "return_taint_map", None)

        # Layer 1+2: per-function taint within each file (with return-taint map)
        for rel_path, language, source_bytes, units in taint_inputs:
            taint_findings.extend(
                TE.analyse_file(language, source_bytes, rel_path, units, return_taint_map=rt_map))

        # Layer 3+4: interprocedural + cross-file across ALL python files
        for rel_path, language, source_bytes, units in taint_inputs:
            taint_findings.extend(
                ia.analyse_with_interproc(rel_path, language, source_bytes, units))

        if not taint_findings:
            return findings

        # index existing findings for dedup: (type, file) -> list of linenos
        existing = {}
        for f in findings:
            existing.setdefault((f.type, f.file), []).append(f)

        def _overlaps(tf):
            cands = existing.get((tf["type"], tf["file"]), [])
            for f in cands:
                # same function, or within a few lines -> consider it the same issue
                if f.function == tf["function"] or abs((f.lineno or 0) - tf["lineno"]) <= 6:
                    return f
            return None

        seen_new = set()
        for tf in taint_findings:
            hit = _overlaps(tf)
            if hit is not None:
                # upgrade the existing finding's confidence + method (taint-proven)
                hit.confidence = max(hit.confidence, tf["confidence"])
                hit.detection_method = "taint-dataflow"
                continue
            # avoid duplicate taint findings among themselves
            key = (tf["type"], tf["file"], tf["function"], tf["lineno"])
            if key in seen_new:
                continue
            seen_new.add(key)
            # carry the real sink location (for interprocedural findings) so the
            # patcher can fix the vulnerability where the dangerous sink actually
            # is, not at the call site.
            sink_info = None
            if tf.get("sink_function"):
                sink_info = {
                    "sink_function": tf["sink_function"],
                    "sink_file": tf.get("sink_file"),
                    "sink_lineno": tf.get("sink_lineno"),
                    "interprocedural": True,
                }
            # build a Finding for a genuinely new taint result
            new_f = Finding(
                matcher_id="taint-engine",
                type=tf["type"],
                cwe=tf["cwe"],
                severity=tf["severity"],
                confidence=tf["confidence"],
                file=tf["file"],
                language=tf.get("language", "python"),
                function=tf["function"],
                lineno=tf["lineno"],
                end_lineno=tf["lineno"],
                source=tf.get("evidence", ""),
                explanation=(
                    f"Taint analysis traced untrusted input to a {tf['type']} sink "
                    f"({tf.get('via','')}). {tf.get('evidence','')}"
                ),
                exploit_scenario="An attacker controls the input that reaches this sink.",
                remediation="Sanitise or parameterise the value before it reaches the sink.",
                detection_method="taint-dataflow",
                dynamic_proof=sink_info,
            )
            # Apply the SAME context-aware FP suppression to taint findings as to
            # matcher findings (browser-vs-server JS, doc/test/analyzer code,
            # string/comment context). Taint findings previously bypassed this.
            from matchers import context_filter as _CF
            _action, _factor, _reason = _CF.evaluate(
                new_f, _CF.classify_file(tf["file"]), self._file_text.get(tf["file"], ""))
            if _action == "drop":
                continue
            if _action == "penalize":
                new_f.confidence = round(new_f.confidence * _factor, 2)
                if _reason:
                    new_f.explanation += f"  [note: {_reason}; confidence reduced]"
                if new_f.confidence < 0.3:
                    continue
            findings.append(new_f)
        return findings

    # ------------------------------------------------------------------
    def _merge_semgrep_findings(self, findings):
        """Phase D: run Semgrep and merge its results, de-duplicating against
        engine findings on (file, line, class). A semgrep result that coincides
        with an engine finding (same file, within a few lines, same class)
        CORROBORATES it (method noted, confidence raised) instead of being
        double-reported; a result the engine has nothing near is added as a new
        complementary finding (with the same context-aware FP suppression)."""
        import sys
        from scanners import semgrep_scanner as SG
        from matchers.base import Finding
        from matchers import context_filter as CF

        res = SG.run_semgrep(self.target_dir)
        if res is None:
            print("[LogicBreaker] Semgrep is not installed; continuing with the engine "
                  "only. Install it (`pip install semgrep`) to add complementary rule "
                  "coverage.", file=sys.stderr)
            return findings
        if not res:
            return findings

        def _cwe_num(c):
            m = re.search(r"\d+", c or "")
            return m.group(0) if m else ""

        by_file = {}
        for f in findings:
            by_file.setdefault(f.file, []).append(f)

        for s in res:
            sfile, sline = s["file"], s["lineno"]
            scwe = _cwe_num(s["cwe"])
            dup = None
            for f in by_file.get(sfile, []):
                if abs((f.lineno or 0) - sline) <= 3:
                    fcwe = _cwe_num(f.cwe)
                    # same class when CWEs match, or when either side lacks a CWE
                    # (proximity alone then implies the same underlying issue).
                    if (scwe and fcwe and scwe == fcwe) or not scwe or not fcwe:
                        dup = f
                        break
            if dup is not None:
                if "semgrep" not in (dup.detection_method or ""):
                    dup.detection_method = (dup.detection_method or "static-heuristic") + " + semgrep"
                dup.confidence = max(dup.confidence, 0.9)
                continue

            nf = Finding(
                matcher_id="semgrep", type=s["type"], cwe=s["cwe"], severity=s["severity"],
                confidence=s.get("confidence", 0.6), file=sfile, language="",
                function="", lineno=sline, end_lineno=sline, source=s.get("message", ""),
                explanation=f"Semgrep rule `{s['check_id']}` matched: {s.get('message', '')}",
                detection_method="semgrep",
            )
            action, factor, reason = CF.evaluate(
                nf, CF.classify_file(sfile), self._file_text.get(sfile, ""))
            if action == "drop":
                continue
            if action == "penalize":
                nf.confidence = round(nf.confidence * factor, 2)
                if nf.confidence < 0.3:
                    continue
            findings.append(nf)
            by_file.setdefault(sfile, []).append(nf)
        return findings

    def _run_matchers(self, units, context):
        from matchers import context_filter as CF

        # cache file-role classification per file
        role_cache = {}

        findings = []
        for unit in units:
            name = unit.get("name", "")
            # skip pure constructors/dunders -- they rarely contain the flaw
            # itself and create noise (e.g. __init__ assigning a balance).
            if name in ("__init__", "__repr__", "__str__", "__eq__", "__hash__"):
                continue

            rel = unit.get("file", "")
            if rel not in role_cache:
                role_cache[rel] = CF.classify_file(rel)
            file_role = role_cache[rel]

            for matcher in self.matchers:
                if not matcher.supports(unit["language"]):
                    continue
                # On the synthetic <module> unit, only run matchers whose flaw
                # genuinely lives at module/top level (debug flag, hardcoded
                # secrets, insecure CORS, mass-assignment config). Function-scope
                # matchers (SQLi, crypto-on-sensitive-data, etc.) need the real
                # function body and would otherwise fire on top-level noise.
                if unit.get("is_module"):
                    if getattr(matcher, "id", "") not in (
                            "debug-mode", "hardcoded-secret", "insecure-cors",
                            "cors-misconfig",  #  actual CORS matcher id
                            "mass-assignment", "csrf-disabled",
                            "tls-verification-disabled", "permissive-file-permissions",
                            "insecure-randomness"):
                        continue
                try:
                    results = matcher.match(unit, context)
                except Exception as e:
                    #  log the matcher failure instead of swallowing it
                    # silently. A matcher crash should never abort the whole
                    # scan, but the user needs to know it happened.
                    import os as _os
                    import sys as _sys
                    if _os.environ.get("LB_AI_DEBUG", "") not in ("", "0", "false", "False"):
                        print(f"[scan_engine] matcher {getattr(matcher, 'id', '?')} "
                              f"crashed on {unit.get('qualname', '?')}: "
                              f"{type(e).__name__}: {e}", file=_sys.stderr, flush=True)
                    results = []
                # context-aware false-positive suppression
                for f in results:
                    action, factor, reason = CF.evaluate(
                        f, file_role, self._file_text.get(rel, ""))
                    if action == "drop":
                        continue
                    if action == "penalize":
                        f.confidence = round(f.confidence * factor, 2)
                        if reason:
                            f.explanation += f"  [note: {reason}; confidence reduced]"
                        # drop very-low-confidence penalized findings entirely
                        if f.confidence < 0.3:
                            continue
                    # ---- Mitigation Recognition Layer ----
                    # if the finding's source code contains a known mitigation
                    # pattern (e.g. ast.literal_eval, _lb_safe_loads, debug=False),
                    # the vulnerability has been fixed → suppress this false positive
                    try:
                        if CF.is_mitigated(f.source or "", f.type):
                            continue
                    except Exception:
                        pass
                    findings.append(f)

        # Collapse matcher-vs-matcher duplicates: when two DIFFERENT matchers
        # report the same (type, file, function), it is the same underlying
        # vulnerability surfaced twice (e.g. the deserialization matcher fires at
        # the source line and the dangerous-sink matcher at the sink line). Keep
        # the single strongest finding. Same-(type,file,function) findings from
        # the SAME matcher are DISTINCT sinks (e.g. eval AND exec in one
        # function) and are all preserved.
        #
        # Also collapse same-line findings with SIMILAR types (e.g. CWE-22
        # "Path Traversal" and CWE-23 "Path Traversal Vulnerability" on the
        # same line are the same vuln classified differently).
        from collections import defaultdict
        import re as _re
        groups = defaultdict(list)
        for f in findings:
            groups[(f.type, f.file, f.function)].append(f)
        deduped = []
        for group in groups.values():
            matcher_ids = {getattr(g, "matcher_id", "") for g in group}
            if len(group) == 1 or len(matcher_ids) == 1:
                deduped.extend(group)
                continue
            # multiple matchers on one vuln -> keep the strongest (highest
            # confidence; tie-break on the deeper/sink line for actionability)
            best = max(group, key=lambda g: (g.confidence, g.lineno or 0))
            deduped.append(best)

        # ---- same-line + similar-type dedup ----
        # if two findings are on the EXACT same line and their type names
        # share a significant word, they are the same vuln → keep the stronger
        final = []
        generic = {"of", "in", "the", "for", "a", "an", "to", "use", "via", "and"}
        for f in deduped:
            is_dup = False
            for existing in final:
                if (getattr(f, "file", "") == getattr(existing, "file", "")
                        and int(getattr(f, "lineno", 0) or 0) > 0
                        and int(getattr(f, "lineno", 0) or 0) == int(getattr(existing, "lineno", 0) or 0)):
                    f_words = set(_re.findall(r"[a-z]+", (getattr(f, "type", "") or "").lower()))
                    e_words = set(_re.findall(r"[a-z]+", (getattr(existing, "type", "") or "").lower()))
                    shared = (f_words & e_words) - generic
                    if shared:
                        # keep the higher confidence one
                        if f.confidence > existing.confidence:
                            final.remove(existing)
                            final.append(f)
                        is_dup = True
                        break
            if not is_dup:
                final.append(f)
        return final

    # ------------------------------------------------------------------
    def llm_triage(self, findings, progress_cb=None):
        """
        Phase C -- the LLM CLASSIFICATION pass (optional; only with a provider).

        The local engine has already DETECTED and VERIFIED a data-flow; the LLM's
        job here is to NAME and RATE it correctly -- and to correct the engine
        when it mislabelled the class (the user's "SSRF reported as XSS" / "SQLi
        reported as Insecure Design" problem). It is MUTUAL correction: the LLM
        may also rule a finding a false positive (an effective sanitizer is
        present), in which case the engine's finding is demoted.

        The LLM is FORCED to return an `evidence` object (line/source/sink/
        sanitizer_present). Without evidence its output is treated as UNVERIFIED
        and is NOT acted upon -- the engine's original finding stands.
        """
        if not self.llm or not self.llm.available:
            return findings

        for i, f in enumerate(findings):
            if progress_cb:
                progress_cb(i + 1, len(findings))
            verdict = self._triage_one(f)
            if verdict is None:
                continue

            evidence = verdict.get("evidence")
            has_evidence = isinstance(evidence, dict) and (
                evidence.get("source") or evidence.get("sink") or evidence.get("line"))
            if not has_evidence:
                # No evidence -> unverified. Do NOT reclassify or demote on an
                # ungrounded opinion; keep the engine's finding as-is.
                f.explanation += "  [note: LLM returned no evidence; classification left unverified]"
                continue

            f.evidence = evidence

            # MUTUAL CORRECTION (a): the LLM rules this a false positive and
            # backs it with evidence (e.g. an effective sanitizer is present).
            if verdict.get("is_vulnerable") is False and float(verdict.get("confidence", 0) or 0) >= 0.6:
                f.status = "LIKELY_FALSE_POSITIVE"
                f.confidence = round(min(f.confidence, 0.2), 2)
                if verdict.get("explanation"):
                    f.explanation = verdict["explanation"]
                continue

            # MUTUAL CORRECTION (b): true positive -> let the LLM fix the LABEL.
            f.detection_method = (f.detection_method or "static-heuristic")
            if "llm" not in f.detection_method:
                f.detection_method += " + llm"

            changes = []
            new_type = (verdict.get("correct_type") or "").strip()
            if new_type and new_type.lower() != (f.type or "").lower():
                changes.append(f"type {f.type!r}→{new_type!r}")
                f.type = new_type
            new_cwe = (verdict.get("correct_cwe") or "").strip()
            if new_cwe and _cwe_ok(new_cwe) and new_cwe.upper() != (f.cwe or "").upper():
                changes.append(f"cwe {f.cwe}→{new_cwe}")
                f.cwe = new_cwe.upper()
            new_sev = (verdict.get("severity") or "").strip().upper()
            if new_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") and new_sev != (f.severity or "").upper():
                changes.append(f"severity {f.severity}→{new_sev}")
                f.severity = new_sev

            if changes:
                f.reclassified = "; ".join(changes)
            if verdict.get("explanation"):
                f.explanation = verdict["explanation"]
                if changes:
                    f.explanation += f"  [LLM reclassified: {f.reclassified}]"
            if verdict.get("exploit_scenario"):
                f.exploit_scenario = verdict["exploit_scenario"]
            if verdict.get("remediation"):
                f.remediation = verdict["remediation"]
            if verdict.get("confidence"):
                f.confidence = round(float(verdict["confidence"]), 2)
        return findings

    # JSON contract the LLM must follow for BOTH the triage and safety-net passes.
    _LLM_CONTRACT = (
        "Respond with ONLY a JSON object (no prose, no markdown fence) with EXACTLY "
        "these keys: {\"is_vulnerable\": bool, \"correct_type\": string, "
        "\"correct_cwe\": \"CWE-###\", \"severity\": \"CRITICAL|HIGH|MEDIUM|LOW\", "
        "\"confidence\": number 0-1, \"evidence\": {\"line\": int, \"source\": string, "
        "\"sink\": string, \"sanitizer_present\": bool}, \"explanation\": string, "
        "\"exploit_scenario\": string, \"remediation\": string}. The `evidence` object is "
        "REQUIRED: quote the ACTUAL untrusted-input source expression and the dangerous sink "
        "call from the code, with the line number. If you cannot point to a real source AND a "
        "real sink, set is_vulnerable=false."
    )

    def _triage_one(self, finding):
        system = (
            "You are a senior application security auditor acting as the CLASSIFIER in a "
            "hybrid SAST pipeline. A precise local taint engine has already detected and "
            "verified a source→sink data-flow; your job is to NAME and RATE it correctly. "
            "Both the engine and you can be wrong, and each corrects the other: if the engine "
            "MISLABELLED the class (e.g. it is really SSRF but was reported as XSS, or SQL "
            "Injection reported as Insecure Design), return the corrected class in "
            "correct_type/correct_cwe and the right severity for the context. If the code is "
            "actually safe because an EFFECTIVE sanitizer is present, set is_vulnerable=false. "
            + self._LLM_CONTRACT
        )
        user = (
            f"Language: {display_name(finding.language)}\n"
            f"Engine's tentative classification: {finding.type} ({finding.cwe}), "
            f"severity {finding.severity}\n"
            f"Engine's reasoning: {finding.explanation}\n"
            f"Reported at line {finding.lineno} in function `{finding.function}`.\n\n"
            f"Code unit:\n```\n{finding.source[:2500]}\n```\n\n"
            "Classify precisely and return the required JSON with the evidence object."
        )
        try:
            return self._llm_chat_json(system, user)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Phase E -- LLM safety net: catch vulns the engine AND Semgrep both missed.
    # ------------------------------------------------------------------
    def llm_safety_net(self, scan_result, findings, progress_cb=None, max_units=40):
        """Send only 🟡 SUSPICIOUS units -- functions that read untrusted input AND
        perform a sensitive operation, but produced NO engine and NO Semgrep
        finding -- to the LLM, under the same forced-evidence contract. Confirmed,
        evidence-backed results are added as new findings. 🟢 safe units (no
        source, or no sensitive op) are NEVER sent (cost + hallucination control).
        No-op when no provider is configured."""
        if not self.llm or not self.llm.available:
            return findings
        suspicious = self._suspicious_units(scan_result, findings)
        if not suspicious:
            return findings
        from matchers.base import Finding
        from matchers import context_filter as CF

        seen_src = set()
        new = []
        for i, u in enumerate(suspicious[:max_units]):
            if progress_cb:
                progress_cb(i + 1, min(len(suspicious), max_units))
            # group identical code: one LLM call per distinct unit body (cost)
            h = hash(u.get("source", ""))
            if h in seen_src:
                continue
            seen_src.add(h)
            verdict = self._safety_net_one(u)
            if not verdict or verdict.get("is_vulnerable") is not True:
                continue
            ev = verdict.get("evidence")
            if not (isinstance(ev, dict) and (ev.get("source") or ev.get("sink"))):
                continue  # forced evidence: none -> unverified -> ignore
            vtype = (verdict.get("correct_type") or "Suspected Vulnerability").strip()
            vcwe = (verdict.get("correct_cwe") or "").strip()
            vcwe = vcwe.upper() if _cwe_ok(vcwe) else "CWE-693"
            sev = (verdict.get("severity") or "MEDIUM").strip().upper()
            if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                sev = "MEDIUM"
            nf = Finding(
                matcher_id="llm-safety-net", type=vtype, cwe=vcwe, severity=sev,
                confidence=round(float(verdict.get("confidence", 0.5) or 0.5), 2),
                file=u.get("file", ""), language=u.get("language", ""),
                function=u.get("qualname") or u.get("name", ""),
                lineno=int(ev.get("line") or u.get("lineno", 0) or 0),
                end_lineno=u.get("end_lineno", u.get("lineno", 0)),
                source=u.get("source", ""),
                explanation=(verdict.get("explanation")
                             or "LLM safety net flagged a vulnerability the engine and Semgrep missed."),
                exploit_scenario=verdict.get("exploit_scenario", ""),
                remediation=verdict.get("remediation", ""),
                detection_method="llm-safety-net",
            )
            nf.evidence = ev
            action, factor, reason = CF.evaluate(
                nf, CF.classify_file(nf.file), self._file_text.get(nf.file, ""))
            if action == "drop":
                continue
            if action == "penalize":
                nf.confidence = round(nf.confidence * factor, 2)
                if nf.confidence < 0.3:
                    continue
            new.append(nf)
        findings.extend(new)
        return findings

    def _suspicious_units(self, scan_result, findings):
        """🟡 = reads untrusted input AND does a sensitive op, but no engine/Semgrep
        finding points at it. Everything else is 🟢 (never sent to the LLM)."""
        from core import taint_engine as TE
        covered_fn = {(f.file, f.function) for f in findings}
        covered_lines = {}
        for f in findings:
            covered_lines.setdefault(f.file, []).append(f.lineno or 0)

        _SENSITIVE = re.compile(
            r"\b(exec|eval|system|popen|spawn|query|execute|cursor|open|unlink|remove|"
            r"rmtree|rename|delete|insert|update|send_?file|redirect|render|deserial|"
            r"unserialize|pickle|yaml|urlopen|curl|fetch|password|passwd|token|secret|"
            r"auth|admin|grant|role|privile|capab|payment|balance|transfer|refund)\b",
            re.IGNORECASE)

        out = []
        for u in scan_result.get("units", []):
            if u.get("is_module"):
                continue
            file = u.get("file", "")
            func = u.get("qualname") or u.get("name", "")
            src = u.get("source", "")
            if not src.strip() or (file, func) in covered_fn:
                continue
            # FIX B3: never send a trivial one-liner -- a real flow needs a body.
            if src.count("\n") < 1:
                continue
            start = u.get("lineno") or 0
            span = src.count("\n") + 1
            if any(start <= ln <= start + span for ln in covered_lines.get(file, [])):
                continue
            lang = u.get("language", "")
            reads_input = (lang in TE.LANG_SOURCES and TE._lang_is_source(src, lang)) or \
                bool(re.search(r"request|\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)|"
                               r"req\.(query|body|params|headers|get)|\binput\s*\(|argv", src))
            # FIX B3: a unit is only 🟡 SUSPICIOUS when it BOTH reads untrusted input
            # AND performs a sensitive op, with no engine/Semgrep finding on it.
            # Anything else is 🟢 safe and is NEVER sent to the LLM (cost +
            # hallucination control).
            if not reads_input or not _SENSITIVE.search(src):
                continue
            out.append(u)
        # FIX B3: deterministic order so the max_units cap keeps the SAME units on
        # every run (re-run reproducibility, alongside temperature 0 + the cache).
        out.sort(key=lambda u: (u.get("file", ""), u.get("lineno") or 0,
                                u.get("qualname") or u.get("name", "")))
        return out

    def _safety_net_one(self, unit):
        system = (
            "You are a senior application security auditor acting as a SAFETY NET in a hybrid "
            "SAST pipeline. A precise local taint engine and Semgrep have ALREADY scanned this "
            "function and flagged NOTHING. Your job is to catch what they MISSED -- especially "
            "unusual coding styles and LOGIC / DESIGN flaws (broken authorization, missing "
            "authentication, IDOR, business-logic abuse) that pattern engines overlook. Be "
            "strict: only report a real, reachable vulnerability driven by attacker-controlled "
            "input. If the function is safe, set is_vulnerable=false. " + self._LLM_CONTRACT
        )
        user = (
            f"Language: {display_name(unit.get('language', ''))}\n"
            f"Function `{unit.get('qualname') or unit.get('name', '')}` "
            f"(the engine and Semgrep found nothing here):\n"
            f"```\n{unit.get('source', '')[:2500]}\n```\n\n"
            "Is there a vulnerability the engine missed? Return the required JSON with evidence."
        )
        try:
            return self._llm_chat_json(system, user)
        except Exception:
            return None
