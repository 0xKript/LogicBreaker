"""
Orchestrator
============

The top-level pipeline that ties every stage together:

  1. Static scan        (ScanEngine over the whole target directory)
  2. LLM triage         (optional, if a provider is configured)
  3. Dynamic exploit    (live probes against a runnable target, in a sandbox)
  4. Link proofs        (attach dynamic proofs to matching static findings)
  5. Auto-patch         (Healer: verified for Python race, language patch /
                         LLM fix / recommendation otherwise)
  6. Build report_data  (consumed by the HTML and PDF reporters)

Every stage is defensive: a failure in the dynamic or patch stage does not
abort the run; the report still contains the static results.
"""

import os
from datetime import datetime


# FIX C3: overall budgets for the fix/patch stage so it can NEVER hang the run
# (mirrors the dynamic stage's budget + watchdog). Each individual fix is already
# bounded in agents/healer.py (sandbox re-launch + LLM call both capped); these
# cap the WHOLE stage:
#   * _FIX_STAGE_BUDGET   -- soft wall-clock budget. Once exceeded we stop taking
#     on new fixes and record every remaining finding as "left unfixed (fix-stage
#     budget exceeded)", then finish and write the report.
#   * _FIX_STAGE_HARD_CAP -- a final watchdog cap (> the soft budget). If the
#     stage somehow still overruns, a daemon-thread backstop abandons it, tears
#     down the sandbox, and returns whatever patches were collected so the run
#     ALWAYS terminates and produces output.
_FIX_STAGE_BUDGET = 120.0
_FIX_STAGE_HARD_CAP = 180.0


class Orchestrator:
    def __init__(self, target_dir, llm=None, sandbox_mgr=None,
                 concurrency=20, enable_dynamic=True, enable_patch=True,
                 max_file_bytes=1_500_000, max_files=None, progress=None,
                 ask_before_fix=None, apply_fixes=False, results_callback=None,
                 min_confidence=0.0, use_semgrep=True, enable_enrich=True,
                 enable_safety_net=False, enable_ai_detect=False,
                 enable_taint=True, require_cross_validation=False, mode="fast"):
        self.target_dir = os.path.abspath(target_dir)
        self.llm = llm
        self.min_confidence = min_confidence
        # MODE: tracks which scan mode we are in (fast/ai/hybrid/dynamic).
        # Used to differentiate behaviour between modes (the bug was that
        # mode=ai and mode=hybrid produced identical output).
        self.mode = mode
        # TAINT ENGINE CONTROL: when False, the taint engine is skipped entirely
        # (mode=ai uses the AI for data-flow analysis instead). Default True so
        # the engine-only benchmark path and fast mode keep full taint analysis.
        self.enable_taint = enable_taint
        # CROSS-VALIDATION: when True (hybrid/dynamic modes), findings that are
        # confirmed by >=2 independent layers (Rule Engine + Taint + AI) get a
        # confidence boost, while findings from only ONE layer are kept but
        # flagged as "single-source" in the audit trail. This makes hybrid mode
        # meaningfully different from AI-only mode.
        self.require_cross_validation = require_cross_validation
        # AI DETECTION: run the AI detector + investigator over the source files
        # and MERGE the confirmed findings with the engine's. This is what lets a
        # run catch a vulnerability class the rule engine has no matcher for
        # (e.g. a weak hash). Gated on an LLM being available; the investigator
        # verifies every AI finding, so nothing unverified reaches the report.
        self.enable_ai_detect = enable_ai_detect
        # Phase D: complementary Semgrep scan in real runs (degrades gracefully
        # if semgrep isn't installed). The benchmark uses ScanEngine directly
        # with the default use_semgrep=False, so it is unaffected.
        self.use_semgrep = use_semgrep
        # Phase G: CVE/CWE enrichment of confirmed findings (MITRE CWE + NVD).
        # Optional and best-effort; never breaks the scan.
        self.enable_enrich = enable_enrich
        # FIX B1: the LLM safety net is the ONLY layer that ADDS findings, so it is
        # the only one that can hallucinate. It is OFF by default -- the engine +
        # Semgrep + Phase-C triage are accurate and deterministic on their own.
        # --deep (enable_safety_net=True) turns it on for users who accept the
        # recall/precision trade-off, behind strict grounding (wise_verdict).
        self.enable_safety_net = enable_safety_net
        self.sandbox_mgr = sandbox_mgr
        self.concurrency = concurrency
        self.enable_dynamic = enable_dynamic
        self.enable_patch = enable_patch
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files
        self.progress = progress or (lambda *a, **k: None)
        # ask_before_fix: optional callable(summary_dict) -> bool, asked per
        # vulnerability before patching (the find->exploit->ASK->fix->verify flow)
        self.ask_before_fix = ask_before_fix
        # results_callback: optional callable(report_data, findings) -> bool.
        # Called AFTER scan+exploit but BEFORE patching, so the UI can show the
        # full Results table first and then ask ONE batched "fix all?" question.
        self.results_callback = results_callback
        # apply_fixes: write verified patches to the real files (after backup)
        self.apply_fixes = apply_fixes
        self.backup_mgr = None

    def run(self):
        from core.scan_engine import ScanEngine

        self.progress("scan", "Scanning source tree…")
        engine = ScanEngine(self.target_dir, llm=self.llm,
                            max_file_bytes=self.max_file_bytes, max_files=self.max_files,
                            use_semgrep=self.use_semgrep,
                            enable_taint=self.enable_taint)
        scan = engine.scan()
        scan["target_dir"] = self.target_dir
        scan["mode"] = self.mode
        findings = scan["findings"]

        # MODE-SPECIFIC CROSS-VALIDATION (hybrid/dynamic only):
        # In hybrid mode, findings confirmed by >=2 independent layers get a
        # confidence boost (the layers agree → higher trust). Single-source
        # findings are kept but flagged for audit transparency. This is what
        # makes hybrid mode meaningfully different from AI-only mode.
        if self.require_cross_validation and findings:
            for f in findings:
                sources = []
                if getattr(f, "detection_method", "") in ("static-heuristic", "taint"):
                    sources.append("engine")
                if getattr(f, "detection_method", "") == "ai-llm":
                    sources.append("ai")
                if getattr(f, "detection_method", "") == "semgrep":
                    sources.append("semgrep")
                # store cross-validation metadata on the finding
                if not hasattr(f, "evidence") or f.evidence is None:
                    f.evidence = {}
                if isinstance(f.evidence, dict):
                    f.evidence["layers"] = sources
                    f.evidence["cross_validated"] = len(set(sources)) >= 2
                # boost confidence when cross-validated (cap at 0.99)
                if len(set(sources)) >= 2:
                    base = float(getattr(f, "confidence", 0.5) or 0.5)
                    f.confidence = min(0.99, round(base + 0.10, 2))
            n_xval = sum(1 for f in findings
                         if isinstance(getattr(f, "evidence", None), dict)
                         and f.evidence.get("cross_validated"))
            scan["cross_validated_findings"] = n_xval

        # Confidence threshold: hide low-confidence findings from every downstream
        # stage (dynamic testing, patching, reporting). Lets the user dial how
        # aggressive the scan is; the default 0.0 keeps everything.
        if self.min_confidence and self.min_confidence > 0.0:
            kept = [f for f in findings
                    if float(getattr(f, "confidence", 0.0) or 0.0) >= self.min_confidence]
            scan["findings"] = kept
            scan["hidden_below_confidence"] = len(findings) - len(kept)
            scan["min_confidence"] = self.min_confidence
            findings = kept

        if self.llm and self.llm.available and findings:
            self.progress("triage", f"LLM triage of {len(findings)} findings…")
            findings = engine.llm_triage(findings)

        # Phase E: LLM safety net -- send only 🟡 suspicious units (read input +
        # sensitive op, no engine/Semgrep finding) to catch missed logic/design
        # bugs. FIX B1: OFF by default (it is the only layer that can hallucinate);
        # enabled only via --deep. Also skipped when no provider is configured.
        if self.enable_safety_net and self.llm and self.llm.available:
            self.progress("safety-net", "LLM safety net over suspicious units (--deep)…")
            findings = engine.llm_safety_net(scan, findings)
            scan["findings"] = findings

        # Phase F: WISE VERDICT -- weigh engine + Semgrep + LLM evidence and issue
        # a decisive ruling per finding. Confirmed findings continue to dynamic /
        # fix / report; dropped ones (effective sanitizer, or an LLM hallucination
        # that fails verification on the real code) are removed SILENTLY here, so
        # they never reach the fixer (section 9). Cached by hash(code)+model.
        import tempfile
        from core.wise_verdict import WiseVerdict
        self.progress("verdict", "Wise Verdict weighing the evidence…")
        _model = self.llm.model if (self.llm and getattr(self.llm, "available", False)) else "engine-only"
        _vcache = os.environ.get("LB_VERDICT_CACHE") or \
            os.path.join(tempfile.gettempdir(), "lb_verdict_cache.json")
        self.verdict_judge = WiseVerdict(model=_model, cache_path=_vcache)
        before = len(findings)
        findings = self.verdict_judge.judge_all(findings)
        scan["findings"] = findings
        scan["verdict_dropped"] = before - len(findings)

        # AI DETECTION PASS: run the AI detector + investigator over the source
        # and merge in any CONFIRMED findings the engine missed (a class it has
        # no matcher for). Each is already verified by the investigator, so it is
        # added as a normal finding. De-duplicated against what we already have.
        if self.enable_ai_detect and self.llm and getattr(self.llm, "available", False):
            self.progress("ai-detect", "AI detector reading the source for missed issues…")
            try:
                from core.ai_detection import run_ai_detection
                ai_diag = {}
                ai_new = run_ai_detection(
                    self.target_dir, self.llm, findings,
                    max_file_bytes=self.max_file_bytes, max_files=self.max_files,
                    progress=None, diag=ai_diag)
                scan["ai_detect_diag"] = ai_diag
                if ai_new:
                    findings = list(findings) + list(ai_new)
                    scan["findings"] = findings
                    scan["ai_detected"] = len(ai_new)
                else:
                    scan["ai_detected"] = 0
            except Exception as e:
                # the AI pass must never break a run; on any failure we simply
                # keep the engine's findings.
                scan["ai_detected"] = 0
                scan["ai_detect_diag"] = {"errors": [f"{type(e).__name__}: {e}"]}

        # Phase G: CVE/CWE enrichment of the CONFIRMED findings -- the TOOL itself
        # queries MITRE CWE + NVD (cached per CWE). Optional, best-effort: any
        # network/timeout failure is swallowed and never breaks the scan.
        if self.enable_enrich and findings:
            self.progress("enrich", "Enriching findings (MITRE CWE / NVD)…")
            try:
                from core import enrichment as _ENR
                _by_cwe = {}
                for f in findings:
                    cwe = getattr(f, "cwe", "") or ""
                    if not cwe:
                        continue
                    if cwe not in _by_cwe:
                        _by_cwe[cwe] = _ENR.enrich_cwe(cwe)
                    if _by_cwe[cwe]:
                        f.enrichment = _by_cwe[cwe]
            except Exception:
                pass  # enrichment is optional and must never break the scan

        dynamic_results = []
        dyn_meta = {"ran": False}
        if self.enable_dynamic and self.sandbox_mgr:
            self.progress("dynamic", "Launching target & running live exploits…")
            # run_dynamic already bounds the probe phase (per-probe cap + overall
            # budget). This watchdog is a FINAL backstop covering the launch phase
            # too (copying the target / a runtime that never returns): the whole
            # dynamic stage can never hang the run.
            dyn_meta = self._run_dynamic_guarded(scan)
            if dyn_meta.get("ran"):
                dynamic_results = dyn_meta.get("results", [])

        self._link_proofs(findings, dynamic_results, dyn_meta)

        # build the report data NOW (before patching) so the caller can show the
        # full Results table + live-exploit summary FIRST, then decide on fixes.
        report_data = {
            "meta": {
                "target": self.target_dir,
                "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "mode": "API-assisted" if (self.llm and self.llm.available) else "fast-scan",
                "provider": (self.llm.provider if (self.llm and self.llm.available) else "none"),
            },
            "stats": scan["stats"],
            "findings": [f.to_dict() for f in findings],
            "dynamic": dynamic_results,
            "patches": [],
        }

        # RESULTS-FIRST UX: if a results callback is provided, show results and ask
        # the SINGLE batched fix question now. The callback returns True/False for
        # "fix all". Only then do we patch.
        do_fix = True
        if self.results_callback is not None:
            do_fix = self.results_callback(report_data, findings)

        patches = []
        if self.enable_patch and do_fix:
            self.progress("patch", "Generating & verifying patches…")
            patches = self._run_patch_guarded(findings, dyn_meta)
        report_data["patches"] = patches
        return report_data, findings, scan

    def _run_old(self):
        from core.scan_engine import ScanEngine
        # (legacy path retained for reference; not used)
        pass

    def _build_report(self, scan, findings, dynamic_results, patches):
        return {
            "meta": {
                "target": self.target_dir,
                "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "mode": "API-assisted" if (self.llm and self.llm.available) else "fast-scan",
                "provider": (self.llm.provider if (self.llm and self.llm.available) else "none"),
            },
            "stats": scan["stats"],
            "findings": [f.to_dict() for f in findings],
            "dynamic": dynamic_results,
            "patches": patches,
        }

    # ------------------------------------------------------------------
    def _run_dynamic_guarded(self, scan, hard_cap=150.0):
        """Run the dynamic stage under a HARD wall-clock cap as a final backstop.
        Even if a launch step blocks (copying a huge target, a runtime that never
        returns, a wedged probe that somehow defeats its own timeout), the whole
        run cannot hang: past hard_cap we abandon the stage, kill the sandbox, and
        continue to reporting with whatever was collected. The worker is a daemon
        thread so it can never block interpreter exit."""
        import threading
        from scanners.dynamic_coordinator import run_dynamic

        box = {"meta": {"ran": False, "reason": "dynamic stage did not start"}}

        def _work():
            try:
                box["meta"] = run_dynamic(scan, self.sandbox_mgr, concurrency=self.concurrency)
            except Exception as e:
                box["meta"] = {"ran": False, "reason": f"dynamic stage error: {e}"}

        t = threading.Thread(target=_work, daemon=True)
        t.start()
        t.join(hard_cap)
        if t.is_alive():
            # blew past the hard cap -> stop waiting and tear down the target so
            # the abandoned worker cannot keep a server alive.
            try:
                self.sandbox_mgr.destroy_all()
            except Exception:
                pass
            return {"ran": False, "timed_out": True,
                    "reason": f"dynamic stage exceeded its {hard_cap:.0f}s hard cap; "
                              f"aborted so the scan finishes and writes the report"}
        return box["meta"]

    # ------------------------------------------------------------------
    def _run_patch_guarded(self, findings, dyn_meta, hard_cap=_FIX_STAGE_HARD_CAP):
        """Run the fix/patch stage under a HARD wall-clock cap as a final backstop
        (FIX C3). The stage already bounds each fix (sandbox re-launch + LLM call
        both capped in the healer) and enforces a soft per-stage budget that
        records the remainder as "left unfixed (fix-stage budget exceeded)". This
        watchdog is the last resort: if the whole stage somehow still blows
        hard_cap, we abandon it, tear down any sandbox (so an abandoned re-launch
        cannot keep a server alive), and return whatever patches were collected --
        the run ALWAYS terminates and writes the report. The worker is a daemon
        thread so it can never block interpreter exit."""
        import threading

        box = []                       # _patch appends patches into this live
        done = threading.Event()

        def _work():
            try:
                self._patch(findings, dyn_meta, out=box)
            except Exception as e:
                box.append({"status": "RECOMMENDATION", "text": f"fix stage error: {e}"})
            finally:
                done.set()

        t = threading.Thread(target=_work, daemon=True)
        t.start()
        done.wait(hard_cap)
        if not done.is_set():
            # blew the hard cap -> stop waiting, tear down the sandbox, finish with
            # whatever was collected so the scan still writes its report.
            try:
                if self.sandbox_mgr is not None:
                    self.sandbox_mgr.destroy_all()
            except Exception:
                pass
            box.append({"status": "LEFT_UNFIXED",
                        "note": "fix stage exceeded its hard cap; remaining fixes "
                                "abandoned so the scan finishes and writes the report"})
        return box

    # ------------------------------------------------------------------
    def _link_proofs(self, findings, dynamic_results, dyn_meta):
        # the dynamic target is a Python (Flask/FastAPI) app, so prefer linking
        # a live proof to a python finding of the same type, and never link the
        # same finding twice.
        linked = set()
        for res in dynamic_results:
            if not res.get("vulnerable"):
                continue
            ftype = res.get("matched_finding_type")
            candidates = [f for f in findings if f.type == ftype and id(f) not in linked]
            # prefer python (the runnable target language), then by confidence
            candidates.sort(key=lambda f: (f.language != "python", -f.confidence))
            if not candidates:
                continue
            f = candidates[0]
            f.status = "CONFIRMED"
            f.detection_method = f.detection_method + " + dynamic"
            f.confidence = max(f.confidence, 0.95)
            f.dynamic_proof = {**res, "entrypoint": dyn_meta.get("entrypoint")}
            linked.add(id(f))

    # ------------------------------------------------------------------
    def _redirect_to_sink(self, finding):
        """For an interprocedural taint finding, the vulnerability is reported at
        the CALL SITE but the dangerous sink lives in another function (possibly
        another file). To fix it correctly we retarget the finding at the sink
        function: load that function's current source and point the finding's
        file/function/lineno at it. Returns True if retargeted."""
        proof = finding.dynamic_proof or {}
        if not proof.get("interprocedural") or not proof.get("sink_function"):
            return False
        import os
        from languages import ts_parser
        sink_file = proof.get("sink_file") or finding.file
        sink_func = proof["sink_function"]
        abs_path = os.path.join(self.target_dir, sink_file)
        if not os.path.exists(abs_path):
            return False
        try:
            with open(abs_path, "rb") as fh:
                data = fh.read()
            units = ts_parser.extract_functions(finding.language, data, sink_file)
        except Exception:
            return False
        fname = sink_func.split(".")[-1]
        for u in units:
            if u.get("name") == fname or u.get("qualname") == sink_func:
                # retarget the finding onto the sink function
                finding.file = sink_file
                finding.function = sink_func
                finding.source = u["source"]
                finding.lineno = u.get("lineno", finding.lineno)
                finding.end_lineno = u.get("end_lineno", finding.lineno)
                return True
        return False

    def _refresh_finding_source(self, finding):
        """Re-extract the current source of the finding's function from disk, so
        a fix computed against a stale (already-patched) snapshot still splices.
        Matches the function by name; falls back to leaving the source as-is."""
        import os
        from languages import ts_parser
        abs_path = os.path.join(self.target_dir, finding.file)
        if not os.path.exists(abs_path):
            abs_path = finding.file if os.path.exists(finding.file) else None
        if not abs_path:
            return
        try:
            with open(abs_path, "rb") as fh:
                data = fh.read()
        except OSError:
            return
        # if the recorded source is still present verbatim, nothing to do
        try:
            if finding.source and finding.source in data.decode("utf-8", "replace"):
                return
        except Exception:
            pass
        try:
            units = ts_parser.extract_functions(finding.language, data, finding.file)
        except Exception:
            return
        fname = (finding.function or "").split(".")[-1]
        for u in units:
            if u.get("name") == fname or u.get("qualname") == finding.function:
                finding.source = u["source"]
                if u.get("lineno"):
                    finding.lineno = u["lineno"]
                return

    def _patch(self, findings, dyn_meta, budget=_FIX_STAGE_BUDGET, out=None):
        import time
        from agents.healer import Healer
        from core.backup_manager import BackupManager
        healer = Healer(self.llm, self.sandbox_mgr)

        # set up a backup manager so originals are saved before ANY file write
        if self.apply_fixes and self.backup_mgr is None:
            self.backup_mgr = BackupManager(self.target_dir)

        # `out`, when provided, is the live results list shared with the watchdog
        # (_run_patch_guarded) so partial progress survives a hard-cap abandonment.
        patches = out if out is not None else []
        # patch confirmed findings first, then high-confidence statics
        order = sorted(findings, key=lambda f: (f.status != "CONFIRMED", -f.confidence))
        patched_targets = set()
        # FIX C3: soft overall budget for the whole fix stage. Each fix is bounded
        # individually, so we always return here between fixes; once the budget is
        # spent we stop taking on new fixes and record the rest as left unfixed.
        deadline = time.time() + budget
        budget_exceeded = False
        for f in order:
            key = (f.type, f.file, f.function)
            if key in patched_targets:
                continue
            if time.time() > deadline:
                budget_exceeded = True
                break
            # attempt a fix for any type the healer can handle. The fixer
            # self-verifies (re-runs the detector / re-attacks), so we don't gate
            # on confidence here -- a fix that doesn't actually close the issue is
            # rejected by the verification step, not pre-filtered.
            from agents.code_fixer import FIXERS as _FIXER_MAP
            _has_fixer = (f.type in _FIXER_MAP) or f.type.startswith("Race Condition")
            if not (_has_fixer or f.dynamic_proof or f.confidence >= 0.6):
                continue

            # ---- the find -> exploit -> ASK -> fix flow ---------------------
            # If an ask callback is provided, ask the user yes/no BEFORE fixing.
            # When they decline, we still record the finding location/type/count
            # but leave the vulnerability in place (no patch computed/applied).
            if self.ask_before_fix is not None:
                summary = {
                    "type": f.type, "severity": f.severity, "file": f.file,
                    "line": f.lineno, "function": f.function,
                    "confirmed": bool(f.dynamic_proof),
                    "confidence": f.confidence,
                }
                try:
                    wants_fix = self.ask_before_fix(summary)
                except Exception:
                    wants_fix = False
                if not wants_fix:
                    patches.append({
                        "status": "LEFT_UNFIXED", "finding_type": f.type, "file": f.file,
                        "line": f.lineno, "function": f.function, "severity": f.severity,
                        "note": "User chose not to fix. Vulnerability left in place; "
                                "location and classification recorded above.",
                    })
                    patched_targets.add(key)
                    continue

            link = f.dynamic_proof if f.dynamic_proof else None
            # INTERPROCEDURAL: if the dangerous sink is in another function/file,
            # retarget the finding at that sink so the fix is applied where the
            # vulnerability actually is (not at the harmless call site).
            self._redirect_to_sink(f)
            # If a previous fix already modified this function, f.source is stale.
            # Re-derive the current source of this function from the file on disk
            # so the fix splices cleanly (handles multiple findings per function).
            if self.apply_fixes:
                self._refresh_finding_source(f)
            try:
                result = healer.heal(self.target_dir, f, link, concurrency=self.concurrency,
                                     backup_mgr=self.backup_mgr)
            except Exception as e:
                result = {"status": "RECOMMENDATION", "text": f"patch error: {e}"}

            if result:
                # apply a verified/language fix to the real file (after backup)
                applicable = result.get("status") in ("VERIFIED_FIX", "LANGUAGE_PATCH")
                if self.apply_fixes and applicable and result.get("abs_path"):
                    full_new = result.get("patched_full_source")
                    if not full_new and result.get("patched_source"):
                        # splice the patched function into the file
                        try:
                            with open(result["abs_path"], "r", encoding="utf-8", errors="replace") as fh:
                                cur = fh.read()
                            if f.source in cur:
                                full_new = cur.replace(f.source, result["patched_source"], 1)
                        except OSError:
                            full_new = None
                    if full_new:
                        try:
                            self.backup_mgr.backup_file(result["abs_path"])
                            with open(result["abs_path"], "w", encoding="utf-8") as fh:
                                fh.write(full_new)
                            result["applied"] = True
                        except Exception as e:
                            result["applied"] = False
                            result["apply_error"] = str(e)
                result["finding_type"] = f.type
                result.setdefault("file", f.file)
                patches.append(result)
                patched_targets.add(key)

        # FIX C3: the budget was spent mid-stage -> record every finding we did NOT
        # get to as "left unfixed (fix-stage budget exceeded)" so the report is
        # complete and the run always terminates.
        if budget_exceeded:
            for f in order:
                key = (f.type, f.file, f.function)
                if key in patched_targets:
                    continue
                patches.append({
                    "status": "LEFT_UNFIXED", "finding_type": f.type, "file": f.file,
                    "line": f.lineno, "function": f.function, "severity": f.severity,
                    "note": "left unfixed (fix-stage budget exceeded)",
                })
                patched_targets.add(key)

        # finalize backups (writes the restore manifest)
        if self.backup_mgr is not None:
            backup_dir = self.backup_mgr.finalize()
            if backup_dir:
                self._backup_dir = backup_dir
        return patches
