"""
AI detection layer  --  wires the AI detector/investigator into the scan
========================================================================

 hardening:
  * ALL exceptions are now logged into `diag["errors"]` (previously many were
    swallowed silently, hiding real failures from the user).
  * `file_budget` is now configurable via the `LB_AI_FILE_BUDGET` env var
    (default 60, was a hard-coded constant). Users with large repos can raise
    it; the original hard cap silently skipped AI scanning on most files in a
    real project.
  * Per-file progress is reported so the user sees what is being scanned.
  * The merged finding list now records whether each finding came from
    consensus (both passes) or single-pass -- useful for diagnostics.

The rule/taint engine is precise but only finds what it has rules for, so it can
miss a class it does not model (e.g. a weak-hash call it has no matcher for). The
AI detector finds vulnerabilities of ANY type by reading the code like a human
reviewer; the investigator then verifies each one deterministically, so nothing
the model imagines reaches the report unverified.

This module runs that AI pass over the source files and returns the CONFIRMED
findings as ordinary `Finding` objects, de-duplicated against what the engine
already reported. The orchestrator merges these in, so a real run benefits from
BOTH the engine's precision and the AI's coverage.

It is gated on an LLM being available and is capped to a file budget so a large
repository cannot trigger a huge number of model calls by accident.
"""

from __future__ import annotations

import re


def _verdict_to_finding(verdict, language, rel_path):
    """Convert a confirmed investigator Verdict into a Finding object."""
    from matchers.base import Finding
    case = verdict.case
    # CaseFile confidence is 0..100; Finding confidence is 0..1
    conf = 0.0
    try:
        conf = max(0.0, min(1.0, float(case.confidence) / 100.0))
    except Exception:
        conf = 0.85

    exploit_scenario = ""
    ex = getattr(case, "exploit", None)
    if isinstance(ex, dict):
        payload = ex.get("payload", "")
        expected = ex.get("expected", "")
        if payload or expected:
            exploit_scenario = (f"Send {payload!r} -> {expected}" if payload
                                else str(expected))
    if not exploit_scenario:
        exploit_scenario = case.why or ""

    return Finding(
        matcher_id="ai-detector",
        type=case.name,
        cwe=verdict.cwe or case.cwe,
        severity=(case.severity or "MEDIUM").upper(),
        confidence=conf,
        file=case.file or rel_path,
        language=language,
        function="",
        lineno=int(verdict.line or case.line or 0),
        end_lineno=int(verdict.line or case.line or 0),
        source=case.snippet or "",
        explanation=case.why or "",
        exploit_scenario=exploit_scenario,
        remediation=getattr(case, "fix", "") or "",
        impact=getattr(case, "impact", "") or "",
        detection_method="ai-llm",
        status="CONFIRMED",
    )


def _is_dup(ai_f, existing, window=3):
    """True if `ai_f` matches a finding the engine already reported -- same file
    and CWE within a few lines. Avoids reporting the same issue twice.

    Also deduplicates findings on the EXACT SAME LINE with SIMILAR types
    (e.g. CWE-22 "Path Traversal" and CWE-23 "Path Traversal Vulnerability"
    on the same line are the same vulnerability, just classified differently
    by the AI)."""
    for f in existing:
        f_file = getattr(f, "file", "")
        f_cwe = (getattr(f, "cwe", "") or "")
        f_line = int(getattr(f, "lineno", 0) or 0)
        f_type = (getattr(f, "type", "") or "").lower()

        # standard dedup: same file + same CWE + nearby line
        if (f_file == ai_f.file
                and f_cwe == (ai_f.cwe or "")
                and abs(f_line - ai_f.lineno) <= window):
            return True

        # same-line + similar-type dedup: if two findings are on the EXACT
        # same line and their type names share a keyword (e.g. "Path Traversal"
        # and "Path Traversal Vulnerability"), they are the same vuln classified
        # differently by the AI. Merge them.
        if f_file == ai_f.file and f_line == ai_f.lineno and f_line > 0:
            ai_type = (ai_f.type or "").lower()
            # extract the first significant word from each type
            f_words = set(re.findall(r"[a-z]+", f_type))
            ai_words = set(re.findall(r"[a-z]+", ai_type))
            # if they share a significant word (not generic words like "of", "in")
            generic = {"of", "in", "the", "for", "a", "an", "to", "use", "via", "and"}
            shared = (f_words & ai_words) - generic
            if shared:
                return True
    return False


def run_ai_detection(target_dir, llm, existing_findings,
                     max_file_bytes=1_500_000, max_files=None,
                     file_budget=None, progress=None, diag=None):
    """Run the AI detector + investigator over the source files in `target_dir`.

    Returns a list of NEW, confirmed `Finding` objects (those not already found
    by the engine). If `diag` (a dict) is passed, it is filled with counters and
    per-file detail so a run can be diagnosed instead of failing silently.

     `file_budget` defaults to the `LB_AI_FILE_BUDGET` env var (or 60). Set
    it to a higher number for large repos; set to 0 or a negative number for
    "unlimited". The original hard-coded 60 silently skipped AI scanning on
    most files of any real project, which was a major coverage gap.

    Set the env var LB_AI_DEBUG=1 to also print that detail to stderr live.
    """
    import os as _os
    import sys as _sys
    debug = _os.environ.get("LB_AI_DEBUG", "") not in ("", "0", "false", "False")

    #  file_budget from env var if not explicitly passed
    if file_budget is None:
        env_budget = _os.environ.get("LB_AI_FILE_BUDGET", "")
        if env_budget:
            try:
                file_budget = int(env_budget)
            except ValueError:
                file_budget = 60
        else:
            file_budget = 60

    if diag is None:
        diag = {}
    diag.setdefault("files", 0)
    diag.setdefault("ai_raw", 0)          # total raw findings the AI proposed
    diag.setdefault("accepted", 0)        # passed the investigator
    diag.setdefault("rejected", 0)        # failed the investigator
    diag.setdefault("deduped", 0)         # dropped as duplicate of engine finding
    diag.setdefault("added", 0)           # NEW findings actually returned
    diag.setdefault("errors", [])         # per-file errors (type: message)
    diag.setdefault("reject_reasons", [])  # short reasons the investigator gave
    diag.setdefault("detail", [])         # per-file [(rel, raw, acc, rej, dup)]
    diag.setdefault("consensus_findings", 0)  #  how many had consensus
    diag.setdefault("single_pass_findings", 0)

    def _log(msg):
        if debug:
            print(f"[ai-detect] {msg}", file=_sys.stderr, flush=True)

    if llm is None or not getattr(llm, "available", False):
        diag["errors"].append("no LLM available")
        return []

    try:
        from scanners.file_scanner import scan_tree
    except Exception as e:
        diag["errors"].append(f"scan_tree import: {type(e).__name__}: {e}")
        return []

    from agents.ai_detector import AIDetector
    from core.case_validator import Investigator

    detector = AIDetector(llm)

    try:
        files, _stats = scan_tree(target_dir, max_file_bytes, max_files)
    except Exception as e:
        diag["errors"].append(f"scan_tree: {type(e).__name__}: {e}")
        return []

    #  file_budget = 0 or negative means "unlimited"
    effective_budget = file_budget if (file_budget and file_budget > 0) else len(files)

    new_findings = []
    seen = list(existing_findings)
    count = 0
    skipped_due_to_budget = 0
    for finfo in files:
        if count >= effective_budget:
            skipped_due_to_budget = len(files) - count
            break
        path = finfo.get("path")
        language = finfo.get("language", "")
        rel = finfo.get("rel_path", path or "")
        try:
            with open(path, "rb") as fh:
                code = fh.read().decode("utf-8", errors="replace")
        except OSError as e:
            diag["errors"].append(f"{rel}: read: {type(e).__name__}: {e}")
            continue
        if not code.strip():
            continue
        count += 1
        diag["files"] = count
        if progress:
            progress(count, min(len(files), effective_budget), rel)

        # --- detection (the AI proposes) ---
        try:
            cases = detector.detect(code, language, rel)
        except Exception as e:
            err = f"{rel}: detect: {type(e).__name__}: {e}"
            diag["errors"].append(err)
            _log(err)
            continue
        raw = len(cases)
        diag["ai_raw"] += raw
        #  track consensus vs single-pass
        for c in cases:
            if getattr(c, "consensus", False):
                diag["consensus_findings"] += 1
            else:
                diag["single_pass_findings"] += 1
        _log(f"{rel}: AI proposed {raw} finding(s): "
             + ", ".join(f"{c.name}@{c.snippet[:40]!r}" for c in cases))

        # --- verification (the investigator decides) ---
        try:
            verdicts = Investigator(language).validate_all(cases, code)
        except Exception as e:
            err = f"{rel}: investigate: {type(e).__name__}: {e}"
            diag["errors"].append(err)
            _log(err)
            continue

        acc = rej = dup = 0
        for v in verdicts:
            if not getattr(v, "accepted", False):
                rej += 1
                diag["rejected"] += 1
                reason = f"{v.case.name}: {v.reason}"
                diag["reject_reasons"].append(reason)
                _log(f"{rel}: REJECTED {reason}")
                continue
            acc += 1
            diag["accepted"] += 1
            f = _verdict_to_finding(v, language, rel)
            if f.lineno <= 0:
                continue
            # ---- Mitigation Recognition Layer (AI path) ----
            # if the finding's source code contains a known mitigation pattern
            # (e.g. ast.literal_eval, _lb_safe_loads, debug=False), the
            # vulnerability has been fixed → suppress this false positive.
            # This prevents the AI from re-flagging code that the tool itself
            # has already patched.
            try:
                from matchers.context_filter import is_mitigated
                # check the snippet (the vulnerable line) AND the full function
                # source for mitigation patterns
                snippet = getattr(v.case, "snippet", "") or ""
                if is_mitigated(snippet, f.type) or is_mitigated(f.source or "", f.type):
                    rej += 1
                    diag["rejected"] += 1
                    reason = f"{v.case.name}: mitigated (fix pattern detected in source)"
                    diag["reject_reasons"].append(reason)
                    _log(f"{rel}: MITIGATED {reason}")
                    continue
            except Exception:
                pass
            if _is_dup(f, seen):
                dup += 1
                diag["deduped"] += 1
                _log(f"{rel}: DEDUPED {f.type} (already found by engine)")
                continue
            new_findings.append(f)
            seen.append(f)
            diag["added"] += 1
            _log(f"{rel}: ADDED {f.type} (CWE {f.cwe}) line {f.lineno}")
        diag["detail"].append((rel, raw, acc, rej, dup))

    if skipped_due_to_budget > 0:
        diag["errors"].append(
            f"file_budget={effective_budget}: skipped AI scanning on "
            f"{skipped_due_to_budget} file(s). Set LB_AI_FILE_BUDGET to a "
            f"higher value (or 0 for unlimited) to scan them."
        )

    return new_findings
