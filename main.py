#!/usr/bin/env python3
"""
LogicBreaker AI -- CLI entry point
=================================

Two ways to run:

  Interactive (recommended for humans):
      python main.py
    -> asks fast-scan vs API, shows a provider menu, prompts for the key,
       then the target path.

  Non-interactive (scripts / CI):
      python main.py --target ./my_project --fast
      python main.py --target ./my_project --provider groq --api-key $GROQ_API_KEY
      python main.py --target ./repo --fast --no-dynamic --html report.html --pdf report.pdf

Exit code is non-zero when CRITICAL/HIGH findings exist (useful as a CI gate).
"""

import sys

# Fix the Windows UnicodeEncodeError crash before rich touches stdout/stderr.
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import argparse  # noqa: E402
import os  # noqa: E402

from cli import ui  # noqa: E402


def build_arg_parser():
    p = argparse.ArgumentParser(
        description="LogicBreaker AI -- multi-language business-logic vulnerability hunter, "
                    "live exploiter & auto-patcher",
    )
    p.add_argument("--target", "-t", help="Path to the codebase to scan")
    p.add_argument("--target-url", dest="target_url",
                   help="Scan a LIVE WordPress site at this URL with WPScan "
                        "(separate mode from code scanning)")
    p.add_argument("--wpscan-token", dest="wpscan_token",
                   help="WPScan API token (or set WPSCAN_API_TOKEN) for its vuln DB")
    p.add_argument("--fast", action="store_true", help="Fast scan: no LLM (fully local)")
    p.add_argument("--provider", help="LLM provider id (claude, openai, gemini, groq, ...)")
    p.add_argument("--api-key", help="API key for the chosen provider (or set its env var)")
    p.add_argument("--skip-key-check", action="store_true",
                   help="Skip the live API-key verification (not recommended)")
    p.add_argument("--model", help="Override the provider's default model")
    p.add_argument("--no-dynamic", action="store_true", help="Skip live exploitation stage")
    p.add_argument("--no-patch", action="store_true", help="Skip auto-patching stage")
    p.add_argument("--no-semgrep", action="store_true",
                   help="Skip the complementary Semgrep scan (engine only)")
    p.add_argument("--no-enrich", action="store_true",
                   help="Skip CVE/CWE enrichment (no MITRE CWE / NVD lookups)")
    p.add_argument("--concurrency", type=int, default=20, help="Concurrent requests for race probes")
    p.add_argument("--max-file-bytes", type=int, default=1_500_000, help="Per-file size cap")
    p.add_argument("--max-files", type=int, default=None, help="Limit number of files scanned")
    p.add_argument("--min-confidence", "--confidence-threshold", dest="min_confidence",
                   type=float, default=0.0, metavar="0.0-1.0",
                   help="Hide findings below this confidence (e.g. 0.6 shows only "
                        "medium-high+ confidence). Default 0.0 = show all.")
    p.add_argument("--out", "-o", default="logicbreaker_report", help="Output directory")
    p.add_argument("--html", help="HTML report filename (default: <out>/report.html)")
    p.add_argument("--pdf", help="PDF report filename (default: <out>/report.pdf)")
    p.add_argument("--json", dest="json_out", help="Also write findings as JSON")
    p.add_argument("--list-matchers", action="store_true", help="List vulnerability detectors and exit")
    p.add_argument("--list-languages", action="store_true", help="List supported languages and exit")
    p.add_argument("--list-runtimes", action="store_true",
                   help="Show which language runtimes are installed on this machine (for live exploitation) and exit")
    p.add_argument("--export-patches", action="store_true",
                   help="Write patches as .patch files + a PR body (no network)")
    p.add_argument("--open-pr", action="store_true",
                   help="Open a GitHub PR with the fixes (needs GITHUB_TOKEN and a git repo target)")
    p.add_argument("--pr-base", default="main", help="Base branch for --open-pr")
    p.add_argument("--init-ci", action="store_true",
                   help="Write GitHub Actions / GitLab CI / pre-commit templates and exit")
    p.add_argument("--non-interactive", action="store_true", help="Never prompt; use flags only")
    p.add_argument("--fix", action="store_true",
                   help="Apply verified fixes to the real files (originals are backed up first)")
    p.add_argument("--interactive-fix", action="store_true",
                   help="After exploiting each vulnerability, ask yes/no before fixing it")
    p.add_argument("--deep", action="store_true",
                   help="Enable the LLM safety net (OFF by default): send suspicious-"
                        "but-unflagged units to the LLM to surface bugs the engine and "
                        "Semgrep missed. May add lower-confidence, LLM-discovered findings.")
    p.add_argument("--no-ai-detect", action="store_true",
                   help="Disable AI detection. By default, when an LLM provider is "
                        "configured, the AI reads every source file to find "
                        "vulnerabilities of ANY type (verified deterministically and "
                        "merged with the engine's findings). This flag turns that off "
                        "and uses the rule engine only.")
    # Enterprise features
    p.add_argument("--compliance", default="all",
                   help="Compliance report: OWASP,PCI-DSS,NIST,ISO,all (default: all)")
    p.add_argument("--sarif", help="Write SARIF 2.1.0 output (for GitHub Code Scanning / CI)")
    p.add_argument("--audit-trail", help="Write audit trail JSON (for SOC 2 / ISO 27001)")
    p.add_argument("--n-passes", type=int, default=3,
                   help="AI consensus passes (default: 3). Findings in all passes get +15 confidence.")
    p.add_argument("--max-workers", type=int, default=0,
                   help="Parallel workers for batch scanning (0 = auto-detect CPU)")
    p.add_argument("--priority-files", default="",
                   help="Comma-separated keywords for high-priority files (auth,payment,admin)")
    p.add_argument("--offline", action="store_true",
                   help="Force offline mode (rule engine only, no AI calls)")
    p.add_argument("--no-cache", action="store_true",
                   help="Disable LLM response cache (re-run all AI calls)")
    p.add_argument("--feedback", help="Load false-positive feedback file (learned patterns)")
    return p


def _run_wpscan_mode(args):
    """Phase H -- scan a LIVE WordPress site with WPScan. Separate from the code
    scan: no engine/Semgrep/LLM, just wpscan's fingerprint + known-CVE lookup,
    rendered through the unified reporter."""
    from datetime import datetime
    ui.banner()
    ui.section("WPScan — live WordPress site scan")
    from integrations import wpscan as WP

    if not WP.is_available():
        ui.warning("wpscan is not installed, so the live WordPress scan cannot run.")
        ui.console.print("[dim]Install it (e.g. `gem install wpscan`, or run the official "
                         "Docker image) and re-run. Its vulnerability database needs an API "
                         "token: pass --wpscan-token or set WPSCAN_API_TOKEN. This mode is "
                         "separate from code scanning (use --target <dir> for files).[/dim]")
        return 2

    url = args.target_url
    ui.info(f"Scanning live site: {url}")
    if not (args.wpscan_token or os.environ.get("WPSCAN_API_TOKEN")):
        ui.warning("No WPScan API token set (--wpscan-token / WPSCAN_API_TOKEN); the plugin/"
                   "theme CVE data from the WPScan DB may be limited or unavailable.")

    results = WP.run_wpscan(url, api_token=args.wpscan_token)
    if results is None:
        ui.warning("wpscan is not installed; cannot scan a live site.")
        return 2

    from matchers.base import Finding
    finding_objs = []
    for r in results:
        cves = ", ".join(r.get("cves", []))
        expl = f"WPScan: {r['title']} in {r['component']}."
        if cves:
            expl += f" Known CVE(s): {cves}."
        f = Finding(
            matcher_id="wpscan", type=r["title"], cwe="CWE-1035", severity="HIGH",
            confidence=0.9, file=url, language="wordpress", function=r["component"],
            lineno=0, end_lineno=0, source="", explanation=expl,
            remediation=(f"Update to {r['fixed_in']} or later." if r.get("fixed_in")
                         else "Update the affected component to a patched version."),
            detection_method="wpscan",
        )
        f.enrichment = {"cwe": "", "source": "WPScan DB",
                        "references": r.get("references", []),
                        "similar_cves": [{"id": c, "summary": "", "cvss": None,
                                          "vector": None} for c in r.get("cves", [])]}
        finding_objs.append(f)

    report_data = {
        "meta": {"target": url, "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
                 "mode": "WPScan (live WordPress site)", "provider": "wpscan"},
        "stats": {"analysable": 1, "functions": 0, "routes": 0, "by_language": {"wordpress": 1}},
        "findings": [f.to_dict() for f in finding_objs],
        "dynamic": [], "patches": [], "wpscan": {"url": url, "results": results},
    }

    ui.section("Results")
    if finding_objs:
        ui.findings_table(report_data["findings"])
    else:
        ui.success("WPScan completed: no known core/plugin/theme vulnerabilities found "
                   "(or the target is not WordPress / blocked the scan).")

    os.makedirs(args.out, exist_ok=True)
    html_path = args.html or os.path.join(args.out, "report.html")
    from reporting import html_report
    try:
        html_report.generate(report_data, html_path)
        ui.success(f"HTML report: {html_path}")
    except Exception as e:
        ui.warning(f"HTML report generation failed: {e}")
    if args.json_out:
        import json
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(report_data, fh, indent=2)
        ui.success(f"JSON report: {args.json_out}")

    return 1 if finding_objs else 0


def main():
    args = build_arg_parser().parse_args()

    if args.list_matchers:
        from matchers.registry import matcher_catalogue
        ui.banner()
        ui.section("Vulnerability detectors")
        for m in matcher_catalogue():
            ui.console.print(f"  [bold]{m['cwe']:10}[/bold] {m['name']}")
        return 0

    if args.list_languages:
        from languages.registry import supported_languages, DEEP_LANGUAGES, display_name
        from languages.ts_loader import installed_languages
        ui.banner()
        ui.section("Languages")
        installed = set(installed_languages())
        ui.console.print(f"[dim]Grammars installed and ready: {len(installed)}[/dim]\n")
        for lang in supported_languages():
            if lang in installed:
                tier = "deep" if lang in DEEP_LANGUAGES else "parsed"
                mark = "[green]●[/green]"
            else:
                tier = "grammar not installed"
                mark = "[dim]○[/dim]"
            ui.console.print(f"  {mark} {display_name(lang):22} [dim]{tier}[/dim]")
        ui.console.print("\n[dim]● = ready   ○ = mapped, install its tree-sitter-<lang> package to enable[/dim]")
        return 0

    if args.list_runtimes:
        from sandbox import runtime_detector as RT
        ui.banner()
        ui.section("Installed language runtimes (for live exploitation)")
        lines, n = RT.summary_lines()
        ui.console.print(f"[dim]Detected {n} runtime(s) on this machine. Live exploitation can "
                         f"launch & attack apps in any language marked ●.[/dim]\n")
        for ln in lines:
            if ln.strip().startswith("●"):
                ui.console.print(f"[green]{ln}[/green]")
            else:
                ui.console.print(f"[dim]{ln}[/dim]")
        ui.console.print("\n[dim]● = runtime installed (live exploitation available)   "
                         "○ = not installed (static detection + correct patch still produced)[/dim]")
        ui.console.print("[dim]Install a language's official runtime to unlock live exploitation "
                         "for it — no tool changes needed.[/dim]")
        return 0

    if args.init_ci:
        from integrations.ci_templates import write_all
        ui.banner()
        ui.section("CI/CD templates")
        target = os.path.abspath(args.target or ".")
        written = write_all(target)
        for name, path in written.items():
            ui.success(f"{name}: {path}")
        return 0

    # ---- WPScan mode (Phase H): LIVE WordPress site, SEPARATE from code scan ---
    if args.target_url:
        return _run_wpscan_mode(args)

    ui.banner()

    # ------------------------------------------------------------------
    # Resolve configuration: interactive unless flags/non-interactive given.
    config = {"mode": "fast", "provider": None, "api_key": None, "target": args.target}
    has_flags = bool(args.target or args.fast or args.provider)
    if not has_flags and not args.non_interactive:
        from cli.interactive import configure_interactively
        config = configure_interactively()
    else:
        # non-interactive: derive mode from flags
        if args.provider and not args.fast:
            config["mode"] = "hybrid"  # default to hybrid when provider is given
            config["provider"] = args.provider
            config["api_key"] = args.api_key
        elif args.fast:
            config["mode"] = "fast"
        if not config["target"]:
            config["target"] = "."

    target = os.path.abspath(config["target"])
    if not os.path.isdir(target):
        ui.error(f"Target path not found or not a directory: {target}")
        return 2

    # ------------------------------------------------------------------
    # Build the LLM client (modes: ai, hybrid, dynamic need it; fast does not).
    mode = config["mode"]
    llm = None
    if mode in ("ai", "hybrid", "dynamic") and config["provider"]:
        from agents.llm_client import LLMClient
        llm = LLMClient(provider=config["provider"], api_key=config["api_key"], model=args.model)
        if not llm.available:
            ui.error(f"API-assisted mode was selected for '{config['provider']}' but no usable "
                     f"API key was provided.")
            ui.console.print(f"[dim]Provide a key with --api-key, set the provider's environment "
                             f"variable, or run with --fast for the no-API mode.[/dim]")
            return 2
        # verify the key actually works (unless explicitly skipped)
        if not getattr(args, "skip_key_check", False):
            ui.info(f"Verifying API key with {config['provider']}…")
            ok, message = llm.validate_key()
            if ok:
                ui.success(message)
            else:
                ui.error(f"API key check failed: {message}")
                ui.console.print("[dim]Fix the key, or run with --fast for the no-API mode "
                                 "(or --skip-key-check to bypass this verification).[/dim]")
                return 2

    # ------------------------------------------------------------------
    from sandbox.sandbox_manager import SandboxManager
    from core.orchestrator import Orchestrator

    # mode determines which stages run:
    #   fast    — engine only, no AI, no dynamic
    #   ai      — AI only (engine still runs for merge, but AI is primary)
    #   hybrid  — engine + AI (merged, cross-validated)
    #   dynamic — engine + AI + live exploitation (launches the app)
    enable_dynamic = (mode == "dynamic") and not args.no_dynamic
    enable_ai = bool(llm and getattr(llm, "available", False)) and not args.no_ai_detect
    enable_patch = not args.no_patch

    sandbox_mgr = SandboxManager() if enable_dynamic else None

    def progress(stage, msg):
        ui.info(msg)

    ui.section("Scan")
    ui.info(f"Target: {target}")
    mode_labels = {
        "fast": "Fast (rule engine only, no AI)",
        "ai": f"AI + API ({config['provider']})",
        "hybrid": f"Hybrid (rule engine + AI, {config['provider']})",
        "dynamic": f"Dynamic (engine + AI + live exploitation, {config['provider']})",
    }
    ui.info(f"Mode: {mode_labels.get(mode, mode)}")
    if enable_ai:
        ui.info("AI detection ON: the AI reads every file to find vulnerabilities of "
                "ANY type (each one verified before it is reported). Use --no-ai-detect "
                "to use the rule engine only.")
    elif not llm:
        ui.info("Tip: choosing an LLM provider turns on AI detection, which finds "
                "issue types the rule engine has no matcher for.")
    if enable_dynamic:
        ui.info("Dynamic mode ON: the tool will launch a sandboxed copy of your app "
                "and fire real exploit probes to confirm vulnerabilities live.")
    if args.deep:
        if llm:
            ui.info("Deep mode ON: the LLM safety net may surface lower-confidence, "
                    "LLM-discovered findings (strictly grounded; the engine stays the "
                    "source of truth).")
        else:
            ui.warning("--deep needs an LLM provider; it is ignored in fast-scan mode.")

    # ---- fix-choice flow --------------------------------------------------
    # When running INTERACTIVELY (the normal `python main.py` flow), we always
    # offer to fix each confirmed vulnerability -- the user should never have to
    # remember a flag. The --interactive-fix flag forces it on too, and
    # --non-interactive / a provided --target turns it off (scripted use).
    interactive_session = not args.non_interactive and not args.target
    want_fix_flow = (args.interactive_fix or interactive_session) and not args.non_interactive

    ask_cb = None
    fix_decisions = {"any_yes": False}
    results_cb = None
    if want_fix_flow:
        # RESULTS-FIRST: show the full findings table + live-exploit summary,
        # THEN ask ONE batched question to fix all vulnerabilities.
        def results_cb(report_data, findings):
            ui.section("Results")
            ui.architect_summary({
                "files": report_data["stats"].get("analysable", 0),
                "functions": report_data["stats"].get("functions", 0),
                "routes": report_data["stats"].get("routes", 0),
                "languages": len(report_data["stats"].get("by_language", {})),
            })
            ui.findings_table(report_data["findings"])
            for d in report_data["dynamic"]:
                ui.dynamic_result(d)
            n = len(findings)
            if n == 0:
                return False
            confirmed = sum(1 for f in findings if getattr(f, "status", "") == "CONFIRMED")
            ui.console.print()
            label = f"[bold]Fix all {n} vulnerabilit" + ("y" if n == 1 else "ies") + "?[/bold]"
            if confirmed:
                label += f" [dim]({confirmed} live-confirmed)[/dim]"
            try:
                from rich.prompt import Confirm
                ans = Confirm.ask("  " + label, default=True)
            except Exception:
                ans = input(f"  Fix all {n} vulnerabilities? [y/N] ").strip().lower() in ("y", "yes")
            fix_decisions["any_yes"] = ans
            return ans

    # in an interactive session, a "yes" to any prompt means we should write the
    # fix to disk -- enable apply_fixes automatically for that case.
    apply_fixes = args.fix or want_fix_flow

    orch = Orchestrator(
        target, llm=llm, sandbox_mgr=sandbox_mgr,
        concurrency=args.concurrency,
        enable_dynamic=enable_dynamic,
        enable_patch=enable_patch,
        max_file_bytes=args.max_file_bytes,
        max_files=args.max_files,
        progress=progress,
        results_callback=results_cb,
        apply_fixes=apply_fixes,
        min_confidence=args.min_confidence,
        use_semgrep=not args.no_semgrep,
        enable_enrich=not args.no_enrich,
        enable_safety_net=args.deep,
        enable_ai_detect=enable_ai,
    )
    try:
        report_data, findings, scan = orch.run()
    finally:
        if sandbox_mgr:
            sandbox_mgr.destroy_all()

    # ------------------------------------------------------------------
    # AI-detection diagnostics: show exactly what the AI pass did, so a run that
    # adds nothing is never a black box. (Only when AI detection actually ran.)
    _diag = scan.get("ai_detect_diag")
    if _diag is not None:
        added = _diag.get("added", 0)
        raw = _diag.get("ai_raw", 0)
        acc = _diag.get("accepted", 0)
        rej = _diag.get("rejected", 0)
        dup = _diag.get("deduped", 0)
        ui.info(f"AI detection: proposed {raw}, verified {acc}, rejected {rej}, "
                f"duplicate of engine {dup}, NEW added {added}.")
        for reason in _diag.get("reject_reasons", [])[:8]:
            ui.console.print(f"    [dim]· rejected — {reason}[/dim]")
        for err in _diag.get("errors", [])[:5]:
            ui.warning(f"AI detection issue: {err}")
        if raw == 0 and not _diag.get("errors"):
            ui.console.print("    [dim]· the AI itself reported no vulnerabilities in "
                             "these files (try a stronger model, e.g. Claude/GPT).[/dim]")
        ui.console.print("    [dim]· run again with LB_AI_DEBUG=1 for full per-file "
                         "detail.[/dim]")

    # ------------------------------------------------------------------
    # Console summary. In interactive mode the Results were already shown by the
    # results callback (before the fix question); show them here only when we
    # did NOT use that callback (scripted / --fix / --non-interactive runs).
    if results_cb is None:
        ui.section("Results")
        ui.architect_summary({
            "files": report_data["stats"].get("analysable", 0),
            "functions": report_data["stats"].get("functions", 0),
            "routes": report_data["stats"].get("routes", 0),
            "languages": len(report_data["stats"].get("by_language", {})),
        })
        ui.findings_table(report_data["findings"])
        for d in report_data["dynamic"]:
            ui.dynamic_result(d)

    # ------------------------------------------------------------------
    # Reports
    os.makedirs(args.out, exist_ok=True)
    html_path = args.html or os.path.join(args.out, "report.html")
    pdf_path = args.pdf or os.path.join(args.out, "report.pdf")

    from reporting import html_report, pdf_report
    html_report.generate(report_data, html_path)
    try:
        pdf_report.generate(report_data, pdf_path)
    except Exception as e:
        ui.warning(f"PDF generation failed ({e}); HTML report still written.")
        pdf_path = None

    if args.json_out:
        import json
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(report_data, fh, indent=2)

    # write patches to disk as .patch files
    patch_dir = os.path.join(args.out, "patches")
    written = 0
    for i, p in enumerate(report_data["patches"]):
        if p.get("diff"):
            os.makedirs(patch_dir, exist_ok=True)
            with open(os.path.join(patch_dir, f"patch_{i+1}.patch"), "w", encoding="utf-8") as fh:
                fh.write(p["diff"])
            written += 1

    ui.section("Output")
    ui.success(f"HTML report: {html_path}")
    if pdf_path:
        ui.success(f"PDF report:  {pdf_path}")
    if written:
        ui.success(f"{written} patch file(s): {patch_dir}/")

    # ---- Enterprise reports: Compliance + SARIF + Audit Trail + Chains ----
    _write_enterprise_reports(args, report_data, findings)

    # applied-fix + backup notice
    applied = [p for p in report_data["patches"] if p.get("applied")]
    if applied:
        ui.success(f"{len(applied)} fix(es) applied to source files and re-verified by re-attack.")
        bdir = getattr(orch, "_backup_dir", None)
        if bdir:
            ui.success(f"Originals backed up to: {bdir}")
            ui.info("Restore anytime with: python -m core.backup_manager restore "
                    f'"{bdir}"')

        # RE-SCAN to prove the fixes closed the vulnerabilities. We verify TWO
        # ways: (1) static + taint re-scan of the files on disk, and (2) for any
        # finding that was CONFIRMED by a live exploit, we RE-LAUNCH the app and
        # RE-ATTACK -- the vulnerability is only "closed" if the live re-attack now
        # FAILS. The "all closed" message only prints when BOTH checks pass.
        ui.section("Re-scan (verifying fixes)")
        from core.scan_engine import ScanEngine
        from agents.code_fixer import FIXERS as _FIXMAP
        from matchers.context_filter import is_mitigated
        rescan = ScanEngine(target, max_file_bytes=args.max_file_bytes,
                            max_files=args.max_files).scan()
        remaining = rescan["findings"]

        # ---- Mitigation Recognition Layer ----
        # Filter out findings where the source code contains a known mitigation
        # pattern (e.g. ast.literal_eval, _lb_safe_loads, debug=False). These
        # are false positives from the regex matchers firing on patched code.
        remaining = [f for f in remaining if not is_mitigated(f.source or "", f.type)]

        # a finding is "fixable" if we have a fixer for its type (or it's a race)
        def _is_fixable(ftype):
            return (ftype in _FIXMAP) or ftype.startswith("Race Condition") \
                or "Command Injection" in ftype or "SQL Injection" in ftype \
                or "Debug Mode" in ftype

        still_fixable = [f for f in remaining if _is_fixable(f.type)]

        # LIVE RE-ATTACK: re-exploit the patched app for any class we confirmed.
        live_still_vulnerable = []
        confirmed_types = {f.get("matched_finding_type") for f in report_data.get("dynamic", [])
                           if f.get("vulnerable")}
        if confirmed_types and not args.no_dynamic:
            try:
                from scanners.dynamic_coordinator import run_dynamic
                from sandbox.sandbox_manager import SandboxManager
                _mgr = SandboxManager()
                _re = ScanEngine(target, max_file_bytes=args.max_file_bytes,
                                 max_files=args.max_files).scan()
                _re["target_dir"] = target
                _dyn = run_dynamic(_re, _mgr, concurrency=args.concurrency)
                _mgr.destroy_all()
                if _dyn.get("ran"):
                    live_still_vulnerable = [r.get("matched_finding_type")
                                             for r in _dyn["results"] if r.get("vulnerable")]
            except Exception:
                pass

        if not remaining and not live_still_vulnerable:
            ui.success("Re-scan clean: 0 vulnerabilities remain. All issues closed and "
                       "verified (static re-scan + live re-attack both pass).")
        elif live_still_vulnerable:
            # the most serious case: the live exploit STILL works after patching.
            ui.warning(f"{len(live_still_vulnerable)} vulnerability(ies) are STILL LIVE-EXPLOITABLE "
                       f"after patching: {', '.join(set(live_still_vulnerable))}. Attempting a "
                       f"stronger fix…")
            orch2 = Orchestrator(target, llm=llm, sandbox_mgr=None,
                                 concurrency=args.concurrency, enable_dynamic=False,
                                 enable_patch=True, max_file_bytes=args.max_file_bytes,
                                 max_files=args.max_files, apply_fixes=True)
            orch2.run()
            # re-verify live one more time
            try:
                from scanners.dynamic_coordinator import run_dynamic
                from sandbox.sandbox_manager import SandboxManager
                _mgr = SandboxManager()
                _re = ScanEngine(target, max_file_bytes=args.max_file_bytes,
                                 max_files=args.max_files).scan()
                _re["target_dir"] = target
                _dyn = run_dynamic(_re, _mgr, concurrency=args.concurrency)
                _mgr.destroy_all()
                final_live = [r.get("matched_finding_type") for r in _dyn.get("results", [])
                              if r.get("vulnerable")] if _dyn.get("ran") else []
            except Exception:
                final_live = []
            if not final_live:
                ui.success("Second pass complete: the live exploit no longer succeeds. "
                           "Vulnerability closed and verified by re-attack.")
            else:
                ui.warning(f"{len(set(final_live))} vulnerability(ies) could not be safely "
                           f"auto-fixed and remain live-exploitable: {', '.join(set(final_live))}. "
                           f"A precise manual fix is described in the report.")
        elif not still_fixable:
            ui.success(f"Re-scan: all auto-fixable vulnerabilities are closed. "
                       f"{len(remaining)} advisory finding(s) remain that need a manual "
                       f"decision (shown in the report) — these have no safe automatic fix.")
        else:
            ui.info(f"{len(still_fixable)} fixable issue(s) still present — running another "
                    f"fix pass…")
            orch2 = Orchestrator(target, llm=llm, sandbox_mgr=None,
                                 concurrency=args.concurrency, enable_dynamic=False,
                                 enable_patch=True, max_file_bytes=args.max_file_bytes,
                                 max_files=args.max_files, apply_fixes=True)
            orch2.run()
            final = ScanEngine(target, max_file_bytes=args.max_file_bytes,
                              max_files=args.max_files).scan()["findings"]
            final_fixable = [f for f in final if _is_fixable(f.type)]
            if not final_fixable:
                ui.success(f"Second pass complete: all auto-fixable vulnerabilities are now "
                           f"closed. {len(final)} advisory finding(s) remain for manual review.")
            else:
                ui.warning(f"{len(final_fixable)} issue(s) could not be safely auto-fixed and "
                           f"were left in place with a recommendation in the report.")
    left = [p for p in report_data["patches"] if p.get("status") == "LEFT_UNFIXED"]
    if left:
        ui.info(f"{len(left)} vulnerability(ies) left unfixed at your request "
                f"(locations recorded in the report).")

    # GitHub / PR integration
    if args.export_patches or args.open_pr:
        from integrations import github_pr
        if args.export_patches:
            exp = github_pr.export_patches(report_data["patches"], os.path.join(args.out, "pr"))
            ui.success(f"Exported {len(exp['patches'])} patch(es) + PR body to {os.path.join(args.out, 'pr')}/")
        if args.open_pr:
            ui.info("Opening GitHub pull request…")
            res = github_pr.open_pull_request(report_data["patches"], target,
                                              base=args.pr_base)
            if res.get("ok"):
                ui.success(f"PR opened: {res['pr_url']}")
            else:
                ui.warning(f"Could not open PR: {res.get('reason')}")

    # CI gate: non-zero exit if Critical/High present
    sev = [f["severity"] for f in report_data["findings"]]
    if "CRITICAL" in sev or "HIGH" in sev:
        return 1
    return 0


def _write_enterprise_reports(args, report_data, findings):
    """Write the enterprise-grade reports: Compliance, SARIF, Audit Trail,
    Exploit Chains, Confidence Scores.

    These are OPTIONAL -- they only run when the user passes the relevant
    flags (--compliance, --sarif, --audit-trail). When run, they produce
    the artifacts government/enterprise auditors require."""
    import json as _json

    # build a unified findings list with all metadata
    unified = []
    for f in findings:
        unified.append({
            "cwe": getattr(f, "cwe", "") or "",
            "name": getattr(f, "type", "") or "",
            "severity": getattr(f, "severity", "MEDIUM"),
            "confidence": float(getattr(f, "confidence", 0.5) or 0.5),
            "file": getattr(f, "file", "") or "",
            "line": int(getattr(f, "lineno", 0) or 0),
            "snippet": getattr(f, "source", "") or "",
            "source": getattr(f, "source", "") or "",
            "why": getattr(f, "explanation", "") or "",
            "impact": getattr(f, "impact", "") or "",
            "fix": getattr(f, "remediation", "") or "",
            "exploit_scenario": getattr(f, "exploit_scenario", "") or "",
            "sources": ["engine"] + (["ai"] if getattr(f, "detection_method", "") == "ai-llm" else []),
            "consensus_count": 1,
            "exploit_proven": getattr(f, "status", "") == "CONFIRMED",
            "fixed": any(p.get("applied") for p in report_data.get("patches", [])
                         if p.get("type", "") == getattr(f, "type", "")),
        })

    # ---- Compliance Mapping ----
    try:
        from reporting.compliance import ComplianceMapper
        mapper = ComplianceMapper()
        cf = [mapper.map_finding(f["cwe"], f["name"], f["file"], f["line"],
                                  f["severity"], f["confidence"]) for f in unified]
        reports = mapper.generate_report(cf, framework=args.compliance)
        ui.section("Compliance Report")
        for fw, rep in reports.items():
            status = "PASS" if rep.overall_status == "PASS" else "FAIL"
            color = "green" if status == "PASS" else "red"
            ui.console.print(f"  [{color}]{status:4s}[/{color}] "
                            f"{rep.framework:25s} {rep.total_findings} findings")
        # write compliance to the JSON output if requested
        if args.json_out:
            compliance_data = {k: mapper.to_dict(v) for k, v in reports.items()}
            with open(args.json_out, "r", encoding="utf-8") as fh:
                existing = _json.load(fh)
            existing["compliance"] = compliance_data
            with open(args.json_out, "w", encoding="utf-8") as fh:
                _json.dump(existing, fh, indent=2)
    except Exception as e:
        ui.warning(f"Compliance report failed: {e}")

    # ---- SARIF Output ----
    if args.sarif:
        try:
            from reporting.sarif_report import write_sarif
            write_sarif(unified, args.sarif)
            ui.success(f"SARIF report: {args.sarif}")
        except Exception as e:
            ui.warning(f"SARIF report failed: {e}")

    # ---- Audit Trail ----
    if args.audit_trail:
        try:
            from core.audit_trail import AuditTrail
            audit = AuditTrail()
            for f in unified:
                audit.log_detection(layer=f["sources"][0] if f["sources"] else "engine",
                                     target=f"{f['file']}:{f['line']}",
                                     finding_name=f["name"], cwe=f["cwe"],
                                     confidence=f["confidence"])
            audit.log(phase="done", action="scan_completed",
                      target=args.target or ".",
                      reason=f"{len(unified)} findings", layer="runner")
            audit.save(args.audit_trail)
            ui.success(f"Audit trail: {args.audit_trail}")
        except Exception as e:
            ui.warning(f"Audit trail failed: {e}")

    # ---- Exploit Chain Detection ----
    try:
        from core.exploit_chain import ExploitChainDetector
        chain_det = ExploitChainDetector()
        chains = chain_det.detect(unified)
        if chains:
            ui.section("Exploit Chains")
            ui.warning(f"Detected {len(chains)} exploit chain(s)!")
            for c in chains:
                ui.console.print(f"  [bold red][{c.combined_severity}][/bold red] "
                                f"[bold]{c.name}[/bold]")
                ui.console.print(f"  [dim]{c.description[:100]}...[/dim]")
            # add chains to JSON
            if args.json_out:
                with open(args.json_out, "r", encoding="utf-8") as fh:
                    existing = _json.load(fh)
                existing["chains"] = [c.to_dict() for c in chains]
                with open(args.json_out, "w", encoding="utf-8") as fh:
                    _json.dump(existing, fh, indent=2)
    except Exception as e:
        # exploit chain detection is best-effort
        pass


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        # user pressed Ctrl-C -- exit quietly, no scary traceback
        try:
            print("\nCancelled.")
        except Exception:
            pass
        sys.exit(130)
