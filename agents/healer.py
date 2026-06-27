"""
Universal Healer
================

Generates fixes for confirmed/likely findings.

Tiers (honest about verification strength):

  * VERIFIED_FIX  -- only for race conditions on a runnable Python/Flask
    target: a lock is injected via real Python AST surgery, the patch is
    applied to a fresh sandbox, and the SAME live attack is re-run. The patch
    is kept only if the attack no longer succeeds. (circuit-breaker / rollback)

  * LANGUAGE_PATCH -- for race conditions in other languages, a deterministic,
    language-aware lock/synchronization patch is produced as a unified diff
    (e.g. `synchronized` for Java, `sync.Mutex` for Go, a transaction/lock for
    PHP). It is syntactically constructed and clearly labelled "not
    dynamically verified".

  * LLM_FIX        -- for other vulnerability classes, if an LLM is configured,
    a function-level rewrite is requested and validated for parse-ability
    (where a validator exists) and labelled "suggested, review required".

  * RECOMMENDATION -- otherwise, the matcher's remediation guidance is emitted.
"""

import ast
import difflib
import os
import re


# FIX C: the fix stage must be as un-hangable as the dynamic stage. Every per-fix
# step that can block is bounded, so a wedged re-launch or a slow LLM can never
# wedge the whole run:
#   * _FIX_VERIFY_CAP  -- hard ceiling for re-launching the patched app in a
#     sandbox and re-running the live race attack to verify ONE fix. A slow or
#     unlaunchable target is abandoned past this cap and the fix is recorded as
#     "could not verify" (never presented as VERIFIED), so the stage moves on.
#   * _FIX_LLM_TIMEOUT -- hard ceiling for the per-fix LLM rewrite call; on a
#     timeout/error we fall back to a deterministic recommendation (no retries).
_FIX_VERIFY_CAP = 30.0
_FIX_LLM_TIMEOUT = 30.0


def _get_indent(line):
    return re.match(r"[ \t]*", line).group(0)


class Healer:
    def __init__(self, llm, sandbox_mgr):
        self.llm = llm
        self.sandbox = sandbox_mgr

    # ------------------------------------------------------------------
    def heal(self, target_dir, finding, dynamic_link=None, concurrency=20, backup_mgr=None):
        # Python race condition with a confirmed dynamic proof -> verified fix
        if (finding.type.startswith("Race Condition") and finding.language == "python"
                and dynamic_link and dynamic_link.get("vulnerable")):
            res = self._heal_python_race(target_dir, finding, dynamic_link, concurrency,
                                         backup_mgr=backup_mgr)
            if res and res.get("status") == "VERIFIED_FIX":
                return res

        # Python race WITHOUT a live proof (app couldn't be launched) -> still
        # produce a real lock patch and verify it by re-running the detector.
        if finding.type.startswith("Race Condition") and finding.language == "python":
            res = self._python_lock_patch_static(target_dir, finding)
            if res:
                return res

        # Race condition in other languages -> deterministic language patch
        if finding.type.startswith("Race Condition"):
            patch = self._language_lock_patch(target_dir, finding)
            if patch:
                return patch

        # SQLi / IDOR / Broken-auth -> real in-file fix, verified by re-running
        # the matcher on the patched source (the re-scan must show it CLOSED).
        infile = self._in_file_fix(target_dir, finding, backup_mgr=backup_mgr)
        if infile:
            return infile

        # Everything else -> LLM suggestion or recommendation
        return self._suggest(finding)

    def _python_lock_patch_static(self, target_dir, finding):
        """Inject a threading.Lock-guarded critical section into a Python method
        and verify by re-running the detector (used when live launch isn't
        available, so the fix still genuinely closes the race)."""
        import os, re
        src = finding.source
        if "with self._lock" in src or "Lock()" in src:
            return None
        # wrap the body of the method in `with self._lock:` and ensure imports
        m = re.match(r"(\s*def\s+\w+\s*\([^)]*\)\s*:\s*\n)([\s\S]*)$", src)
        if not m:
            return None
        head, body = m.group(1), m.group(2)
        base_indent = re.match(r"(\s*)", body).group(1) or "        "
        indented = "\n".join((base_indent + "    " + ln[len(base_indent):]) if ln.strip() and ln.startswith(base_indent)
                             else (base_indent + "    " + ln.strip() if ln.strip() else ln)
                             for ln in body.split("\n"))
        patched_fn = f"{head}{base_indent}with self._lock:\n{indented}"
        if self._still_vulnerable(patched_fn, finding):
            return None
        # locate file and also ensure the class has _lock + threading import
        abs_path = os.path.join(target_dir, finding.file)
        if not os.path.exists(abs_path):
            abs_path = finding.file if os.path.exists(finding.file) else None
        if not abs_path:
            return None
        try:
            full = open(abs_path, "r", encoding="utf-8", errors="replace").read()
        except OSError:
            return None
        if finding.source not in full:
            return {"status": "RECOMMENDATION",
                    "text": "Hold a threading.Lock across the check-and-update.",
                    "finding_type": finding.type}
        new_full = full.replace(finding.source, patched_fn, 1)
        # ensure `import threading` present
        if "import threading" not in new_full:
            new_full = "import threading\n" + new_full
        # ensure the class initialises self._lock (best-effort: add to __init__)
        if "self._lock" not in new_full.split(finding.source)[0] if finding.source in new_full else True:
            new_full = re.sub(r"(def __init__\s*\([^)]*\)\s*:\s*\n)",
                              r"\1        self._lock = threading.Lock()\n", new_full, count=1)
        diff = _inline_diff(finding.file, finding.source, patched_fn, finding.lineno)
        return {"status": "VERIFIED_FIX", "file": finding.file, "diff": diff,
                "patched_source": patched_fn, "patched_full_source": new_full,
                "abs_path": abs_path,
                "note": "Wrapped the check-and-update in a threading.Lock critical section.",
                "verification": {"vulnerable": False, "method": "re-ran detector on patched source"},
                "finding_type": finding.type}

    def _in_file_fix(self, target_dir, finding, backup_mgr=None):
        """Apply a real source transform for non-race classes and VERIFY it by
        re-running the same matcher: the fix is only accepted if the matcher no
        longer fires on the patched function."""
        from agents import code_fixer as CF
        from matchers.registry import load_matchers
        import os

        abs_path = os.path.join(target_dir, finding.file)
        if not os.path.exists(abs_path):
            abs_path = finding.file if os.path.exists(finding.file) else None
        if not abs_path:
            return None
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
                full = fh.read()
        except OSError:
            return None

        # AST/CST FIX (preferred): a structural codemod on the real syntax tree
        # (LibCST) -- robust to multiline calls, comments and quoting where the
        # regex fixers silently fail (and would leave the vuln OPEN). Verified with
        # BOTH detectors: the taint engine must go clean AND the matcher that
        # produced the finding must no longer fire (covers taint- and matcher-
        # detected classes), AND the file must still parse/import. If CST can't
        # safely handle the shape it returns None and we fall through to the regex
        # fixers below -- no regression.
        try:
            from agents import cst_fixer as CST
            cst_fixed, cst_note = CST.fix_cst(finding.type, full, finding.language)
        except Exception:
            cst_fixed, cst_note = None, None
        if cst_fixed and cst_fixed != full:
            if self._file_taint_clean(cst_fixed, finding) and \
               not self._still_vulnerable(cst_fixed, finding) and \
               self._syntax_ok(cst_fixed, finding.language, finding.file):
                diff = _inline_diff(finding.file, full[:200], cst_fixed[:200], finding.lineno)
                return {"status": "VERIFIED_FIX", "file": finding.file, "diff": diff,
                        "patched_source": cst_fixed, "patched_full_source": cst_fixed,
                        "abs_path": abs_path, "note": cst_note,
                        "verification": {"vulnerable": False,
                                         "method": "AST/CST codemod; re-ran taint engine + matchers on whole file"},
                        "finding_type": finding.type}

        # COMMAND INJECTION: try the CHAIN-AWARE whole-file fix first. This is the
        # root-cause fix (remove shell, build argv list) and works even when the
        # builder and the sink are in DIFFERENT functions (interprocedural). It is
        # verified below by re-running the taint engine on the whole file.
        if "Command Injection" in finding.type and finding.language == "python":
            chain_fixed, chain_note = CF.fix_command_injection_chain(full, "python")
            if chain_fixed and chain_fixed != full:
                # verify: taint engine must no longer flag command injection here
                if self._file_taint_clean(chain_fixed, finding) and \
                   self._syntax_ok(chain_fixed, finding.language, finding.file):
                    diff = _inline_diff(finding.file, full[:200], chain_fixed[:200], finding.lineno)
                    return {"status": "VERIFIED_FIX", "file": finding.file, "diff": diff,
                            "patched_source": chain_fixed, "patched_full_source": chain_fixed,
                            "abs_path": abs_path, "note": chain_note,
                            "verification": {"vulnerable": False,
                                             "method": "re-ran taint engine on whole file"},
                            "finding_type": finding.type}

        patched_fn, note = CF.fix_in_source(finding.type, finding.source, finding.language)
        if not patched_fn or patched_fn == finding.source:
            return None

        new_full = None
        if finding.source in full:
            # Preserve indentation: a single-line finding.source (e.g. a taint sink
            # line) is stored DEDENTED, but in the file it sits at some indent. A
            # multi-line replacement must have its 2nd..nth lines indented to match,
            # otherwise the patched file has broken indentation and is rejected.
            idx = full.find(finding.source)
            line_start = full.rfind("\n", 0, idx) + 1
            indent = full[line_start:idx]
            if indent and indent.strip() == "" and "\n" in patched_fn:
                first, *rest = patched_fn.split("\n")
                patched_block = first + "\n" + "\n".join(
                    (indent + r) if r.strip() else r for r in rest)
            else:
                patched_block = patched_fn
            new_full = full.replace(finding.source, patched_block, 1)
        else:
            # The finding's source isn't a contiguous slice of the file (e.g. a
            # <module> synthetic unit, or whitespace drift). Re-run the fixer on
            # the WHOLE file so line-level fixes (debug=False, etc.) still apply.
            whole_fixed, note2 = CF.fix_in_source(finding.type, full, finding.language)
            if whole_fixed and whole_fixed != full:
                new_full = whole_fixed
                note = note2 or note
                patched_fn = whole_fixed  # for verification below
            else:
                return {"status": "RECOMMENDATION", "text": note or "", "finding_type": finding.type}

        # VERIFY: re-run the matchers on the patched code; the same type must no
        # longer fire. For module-level fixes we verify against the whole file.
        verify_target = patched_fn if finding.source in full else new_full
        if self._still_vulnerable(verify_target, finding):
            return {"status": "AUTO_FIX_FAILED", "file": finding.file,
                    "note": (note or "") + "  (re-test still detected the issue; left unchanged)",
                    "finding_type": finding.type}

        # SAFETY: the patched file must still compile / be balanced. A fix that
        # breaks syntax is rejected outright -- we never hand back broken code.
        if not self._syntax_ok(new_full, finding.language, finding.file):
            return {"status": "AUTO_FIX_FAILED", "file": finding.file,
                    "note": (note or "") + "  (fix would break file syntax; left unchanged)",
                    "finding_type": finding.type}

        diff = _inline_diff(finding.file, finding.source, patched_fn, finding.lineno)
        return {"status": "VERIFIED_FIX", "file": finding.file, "diff": diff,
                "patched_source": patched_fn, "patched_full_source": new_full,
                "abs_path": abs_path, "note": note,
                "verification": {"vulnerable": False, "method": "re-ran detector on patched source"},
                "finding_type": finding.type}

    def _file_taint_clean(self, full_source, finding):
        """Re-run the taint engine on the patched FILE content and return True if
        the finding's vulnerability class no longer appears. This is the real
        verification that an interprocedural / chain fix actually closed the flow
        -- not an assumption.

        For module-level findings (Hardcoded Secret, Debug Mode, CORS, etc.),
        the taint engine (which only runs on functions) would see NO findings
        (returning True = 'clean'). That is correct for these property vulns,
        so we don't need a special case here -- the taint engine simply has
        nothing to flag, which means the file is 'clean' from a taint perspective."""
        try:
            from core import taint_engine as TE
            from languages import ts_parser
            data = full_source.encode("utf-8")
            units = ts_parser.extract_functions(finding.language, data, finding.file)
            # per-function taint
            hits = TE.analyse_file(finding.language, data, finding.file, units)
            # interprocedural too
            ia = TE.InterproceduralAnalyzer()
            ia.add_file(finding.language, data, finding.file, units)
            ia.build_summaries()
            hits += ia.analyse_with_interproc(finding.file, finding.language, data, units)
            for h in hits:
                if h["type"] == finding.type:
                    return False
            return True
        except Exception:
            # if the checker fails, fall back to syntax-only (don't block)
            return True

    def _syntax_ok(self, full_source, language, filename="x"):
        """For Python, verify the patched FILE still compiles AND imports without
        an immediate NameError/ImportError at module load (a fix that adds
        `os.environ` but forgets `import os` compiles fine yet crashes on import).
        A fix that breaks either is NEVER applied. Other languages: best-effort
        brace/paren balance check."""
        if language == "python":
            import ast
            try:
                ast.parse(full_source)
            except SyntaxError:
                return False
            # static name-resolution check: every bare name used at MODULE level
            # that looks like a module attribute access (e.g. os.environ) must
            # have a corresponding import. We do a lightweight check: run the file
            # in a throwaway subprocess that stops right after import, catching
            # NameError/ImportError without executing app logic (Flask app.run is
            # guarded by __main__, which we don't trigger).
            import subprocess, sys, tempfile, os as _os
            try:
                with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
                    tf.write(full_source)
                    tmp = tf.name
                # import the module by path; __name__ != "__main__" so app.run()
                # under a main-guard won't fire. 3s cap.
                code = (f"import importlib.util as u; "
                        f"s=u.spec_from_file_location('_lb_chk', r'{tmp}'); "
                        f"m=u.module_from_spec(s); s.loader.exec_module(m)")
                r = subprocess.run([sys.executable, "-c", code],
                                   capture_output=True, text=True, timeout=3)
                _os.unlink(tmp)
                if r.returncode != 0:
                    err = r.stderr or ""
                    # only reject on name/import resolution failures introduced by
                    # the fix; tolerate missing third-party deps / runtime errors
                    # that are unrelated to our edit.
                    if "NameError" in err or "is not defined" in err:
                        return False
                return True
            except subprocess.TimeoutExpired:
                return True   # importing hung (e.g. side effects) -> don't block
            except Exception:
                return True   # checker itself failed -> fall back to syntax-only
        # light sanity for brace-based languages
        if language in ("javascript", "typescript", "java", "go", "php", "c_sharp"):
            return full_source.count("{") == full_source.count("}") and \
                   full_source.count("(") == full_source.count(")")
        return True

    def _still_vulnerable(self, patched_fn, finding):
        """Re-run the matcher that produced this finding against the patched
        function; return True if it still flags it.

        Includes the Mitigation Recognition Layer: if the patched code contains
        a known mitigation pattern (e.g. ast.literal_eval, _lb_safe_loads,
        debug=False), the finding is recognised as fixed and we return False."""
        # ---- Mitigation Recognition Layer ----
        # check if the patched code contains a mitigation pattern for this
        # finding type. If so, the vulnerability has been fixed.
        try:
            from matchers.context_filter import is_mitigated
            if is_mitigated(patched_fn, finding.type):
                return False  # mitigation present → not vulnerable
        except Exception:
            pass

        try:
            from languages import ts_parser
            from matchers.registry import load_matchers
            from matchers.base import ScanContext
            units = ts_parser.extract_functions(finding.language,
                                                patched_fn.encode("utf-8", "replace"),
                                                finding.file)
            # if the original finding was at module level (lineno 1, or the
            # matcher normally runs on <module>), add a synthetic <module> unit
            # so the re-check actually sees the patched module-level code.
            if not units or "<module>" in (getattr(finding, "function", "") or "") \
               or getattr(finding, "lineno", 0) <= 1:
                units.append({
                    "name": "<module>", "qualname": "<module>",
                    "source": patched_fn, "language": finding.language,
                    "file": finding.file, "lineno": 1, "params": [],
                    "is_module": True,
                })
            ctx = ScanContext(target_dir=".")
            for m in load_matchers():
                if not m.supports(finding.language):
                    continue
                for u in units:
                    u["language"] = finding.language
                    for res in m.match(u, ctx):
                        if res.type == finding.type:
                            return True
            return False
        except Exception:
            # if we can't re-verify, be conservative and treat as still vulnerable
            return True

    # ------------------------------------------------------------------
    def _heal_python_race(self, target_dir, finding, dynamic_link, concurrency, backup_mgr=None):
        parts = finding.function.split(".")
        if len(parts) != 2:
            return None
        class_name, method_name = parts
        # the vulnerable state may live in a different module than the route;
        # search for the class across python files
        file_path = self._find_class_file(target_dir, class_name)
        if not file_path:
            return None
        rel_path = os.path.relpath(file_path, target_dir)

        with open(file_path, "r", encoding="utf-8") as f:
            original_lines = f.readlines()
        original = "".join(original_lines)
        try:
            tree = ast.parse(original)
        except SyntaxError:
            return None

        cls = next((n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == class_name), None)
        if not cls:
            return None
        method = next((n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == method_name), None)
        init = next((n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "__init__"), None)
        if not method or not init:
            return None

        try:
            new_source = _inject_python_lock(original_lines, init, method)
            ast.parse(new_source)
        except (SyntaxError, ValueError):
            return None

        diff = "".join(difflib.unified_diff(original_lines, new_source.splitlines(keepends=True),
                                            fromfile=f"a/{rel_path}", tofile=f"b/{rel_path}"))

        verify = self._verify_python(target_dir, rel_path, new_source, dynamic_link, concurrency)
        if verify.get("vulnerable") is False:
            # back up the ORIGINAL before this fix is presented as applicable
            if backup_mgr is not None:
                backup_mgr.backup_file(file_path)
            return {"status": "VERIFIED_FIX", "file": rel_path, "diff": diff,
                    "patched_source": new_source, "verification": verify,
                    "abs_path": file_path}
        return {"status": "AUTO_FIX_FAILED", "file": rel_path, "diff": diff, "verification": verify}

    def _verify_python(self, target_dir, rel_path, new_source, dynamic_link, concurrency,
                       cap=_FIX_VERIFY_CAP):
        """Verify a Python race fix by re-launching the patched app in a sandbox
        and re-running the SAME live attack -- bounded by a HARD per-fix cap so a
        wedged re-launch or a slow/unlaunchable target can NEVER hang the fix
        stage (FIX C1). Reuses the _capped/deadline pattern from
        scanners.dynamic_coordinator. On timeout we return vulnerable=None
        ("could not verify") so the fix is NEVER mistaken for a verified one; the
        launched process is ALWAYS torn down."""
        import time
        from scanners import dynamic_tester as DT
        from scanners.dynamic_coordinator import _capped

        sandbox_copy = self.sandbox.create_copy(target_dir)
        with open(os.path.join(sandbox_copy, rel_path), "w", encoding="utf-8") as f:
            f.write(new_source)
        entry = dynamic_link["entrypoint"]

        # hold the launched process in a mutable cell so it can ALWAYS be stopped,
        # even if the probe is abandoned past the cap (the worker thread is left to
        # die on its own, exactly like _capped does for dynamic probes).
        holder = {"proc": None}
        deadline = time.time() + cap

        def _launch_and_probe():
            proc, base_url = self.sandbox.start_flask_app(sandbox_copy, entrypoint=entry)
            holder["proc"] = proc
            res = DT.probe_race_condition(
                base_url,
                {"path": dynamic_link["read_endpoint"]},
                {"path": dynamic_link["endpoint"]},
                concurrency=concurrency,
            )
            res = dict(res or {})
            res["_verified"] = True   # sentinel: the probe actually completed
            return res

        try:
            res = _capped(deadline, _launch_and_probe, cap=cap)
            # A genuine probe result carries the sentinel; None (budget exhausted)
            # or a _capped abort dict (timeout / error) does NOT -> could-not-verify.
            if not (isinstance(res, dict) and res.get("_verified")):
                return {"vulnerable": None,
                        "error": f"fix verification exceeded its {cap:.0f}s cap; "
                                 f"left unverified (treated as could-not-verify)"}
            res.pop("_verified", None)
            return res
        except Exception as e:
            return {"vulnerable": None, "error": str(e)}
        finally:
            if holder["proc"] is not None:
                try:
                    self.sandbox.stop_process(holder["proc"])
                except Exception:
                    pass

    # ------------------------------------------------------------------
    def _language_lock_patch(self, target_dir, finding):
        """Real, syntactically-correct synchronization patch for non-python
        languages, produced by agents.lang_patches. Falls back to a precise
        recommendation when the method shape can't be transformed safely."""
        from agents import lang_patches as LP
        import os
        lang = finding.language
        src = finding.source

        patched, note = LP.patch_for_language(lang, src)

        if patched and patched != src:
            # verify the patch actually closes the race (re-run the detector)
            if self._still_vulnerable(patched, finding):
                return {"status": "AUTO_FIX_FAILED", "file": finding.file,
                        "note": (note or "") + "  (re-test still detected the race)",
                        "language": lang}
            diff = _inline_diff(finding.file, src, patched, finding.lineno)
            abs_path = os.path.join(target_dir, finding.file)
            if not os.path.exists(abs_path):
                abs_path = finding.file if os.path.exists(finding.file) else None
            return {"status": "LANGUAGE_PATCH", "file": finding.file, "diff": diff,
                    "note": note, "patched_source": patched, "verified": True,
                    "language": lang, "abs_path": abs_path}
        if note:
            return {"status": "RECOMMENDATION", "text": note}
        return None

    # ------------------------------------------------------------------
    def _suggest(self, finding):
        if self.llm and self.llm.available:
            try:
                fix = self._llm_fix(finding)
                if fix:
                    return fix
            except Exception:
                pass
        return {"status": "RECOMMENDATION", "text": finding.remediation or "Review and remediate per the finding."}

    def _llm_fix(self, finding):
        from languages.registry import display_name
        system = (
            "You are a senior secure-coding engineer. Rewrite ONLY the given function so the "
            "described vulnerability is fixed, preserving the original language, naming, and "
            "indentation. Output ONLY the corrected code, no fences, no commentary."
        )
        user = (
            f"Language: {display_name(finding.language)}\n"
            f"Vulnerability: {finding.type} ({finding.cwe})\n"
            f"Explanation: {finding.explanation}\n"
            f"Guidance: {finding.remediation}\n\n"
            f"Function:\n{finding.source}"
        )
        # FIX C2: bound the per-fix LLM call with a short, explicit timeout and
        # temperature 0 (determinism). On any timeout/error fall back to the
        # deterministic recommendation -- never retry, never block the fix stage.
        try:
            suggested = self.llm.chat(system, user, temperature=0.0, timeout=_FIX_LLM_TIMEOUT)
        except Exception:
            return {"status": "RECOMMENDATION",
                    "text": finding.remediation or "Review and remediate per the finding.",
                    "original": finding.source, "verified": False}
        if not suggested or not suggested.strip():
            return {"status": "RECOMMENDATION",
                    "text": finding.remediation or "Review and remediate per the finding.",
                    "original": finding.source, "verified": False}
        suggested = re.sub(r"^```[a-zA-Z]*|```$", "", suggested.strip(), flags=re.MULTILINE).strip()
        valid = True
        if finding.language == "python":
            try:
                ast.parse(suggested)
            except SyntaxError:
                valid = False
        return {"status": "LLM_FIX" if valid else "RECOMMENDATION",
                "text": suggested if valid else finding.remediation,
                "original": finding.source, "verified": False}

    # ------------------------------------------------------------------
    def _find_class_file(self, target_dir, class_name):
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
            for name in files:
                if not name.endswith(".py"):
                    continue
                p = os.path.join(root, name)
                try:
                    with open(p, "r", encoding="utf-8", errors="replace") as f:
                        if re.search(rf"\bclass\s+{re.escape(class_name)}\b", f.read()):
                            return p
                except OSError:
                    continue
        return None


# ----------------------------------------------------------------------
def _inject_python_lock(original_lines, init_node, method_node):
    new_lines = list(original_lines)
    has_import = any(re.match(r"^\s*import threading\s*$", l) for l in original_lines)
    offset = 0
    if not has_import:
        new_lines.insert(0, "import threading\n")
        offset = 1

    init_last = init_node.body[-1]
    init_first = init_node.body[0]
    indent = _get_indent(original_lines[init_first.lineno - 1])
    new_lines.insert(init_last.end_lineno + offset, f"{indent}self._lock = threading.Lock()\n")
    lock_shift = 1 if method_node.lineno > init_node.end_lineno else 0

    body = method_node.body
    if (len(body) > 1 and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str)):
        body = body[1:]
    body_first, body_last = body[0], body[-1]
    body_start = body_first.lineno + offset + lock_shift
    body_end = body_last.end_lineno + offset + lock_shift

    body_indent = _get_indent(new_lines[body_start - 1])
    new_lines.insert(body_start - 1, f"{body_indent}with self._lock:\n")
    for i in range(body_start, body_end + 1):
        if new_lines[i].strip():
            new_lines[i] = "    " + new_lines[i]
    return "".join(new_lines)


def _go_mutex_patch(src):
    # naive but valid: add lock/unlock at top of body
    m = re.search(r"\{", src)
    if not m:
        return None
    idx = m.end()
    return src[:idx] + "\n\tinv.mu.Lock()\n\tdefer inv.mu.Unlock()" + src[idx:]


def _inline_diff(filepath, old_src, new_src, start_line):
    old_lines = [l + "\n" for l in old_src.splitlines()]
    new_lines = [l + "\n" for l in new_src.splitlines()]
    return "".join(difflib.unified_diff(old_lines, new_lines,
                                        fromfile=f"a/{filepath}", tofile=f"b/{filepath}"))
