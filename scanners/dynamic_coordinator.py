"""
Dynamic coordinator
===================

Decides which live probes apply to the discovered routes, launches the target
app once in the sandbox, runs every applicable probe, and links confirmed
results back to the corresponding static findings.

This is what makes the dynamic phase work on *arbitrary* endpoints: it
classifies routes by shape (a numeric-read GET, a consume POST, an id-bearing
GET, a query GET) instead of looking for hardcoded paths.
"""

import concurrent.futures
import os
import re
import time

from scanners import dynamic_tester as DT

# Dynamic-stage safety rails (the dynamic phase must NEVER hang the whole run):
#   * _PROBE_CAP   -- hard ceiling for any single probe. A probe can wedge the
#                     target (command-injection `sleep`, SSRF to a blackholed
#                     host, a streaming/slow-trickle response that defeats the
#                     per-request read timeout), so each probe runs in its own
#                     worker and is abandoned past this cap.
#   * _DYNAMIC_BUDGET -- overall wall-clock budget for the whole probe phase.
#                     When it is exhausted, remaining probes are skipped and the
#                     scan continues to reporting with whatever was collected.
_PROBE_CAP = 12.0
_DYNAMIC_BUDGET = 90.0


def _capped(deadline, fn, *args, cap=_PROBE_CAP, **kwargs):
    """Run one probe with a HARD timeout while respecting the overall stage
    `deadline`. Returns the probe result; None when the budget is already
    exhausted (caller should stop); or a clean 'aborted' result if the probe
    overran or raised. NEVER blocks longer than its slice -- a stuck probe thread
    is left to finish on its own (its own request timeouts end it) while the scan
    moves on, so the run always terminates."""
    remaining = deadline - time.time()
    if remaining <= 0:
        return None
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    fut = ex.submit(fn, *args, **kwargs)
    try:
        return fut.result(timeout=min(cap, remaining))
    except concurrent.futures.TimeoutError:
        return {"attempted": True, "vulnerable": False,
                "error": f"probe exceeded its {cap:.0f}s cap and was aborted to keep the scan moving"}
    except Exception as e:
        return {"attempted": True, "vulnerable": False, "error": f"probe error: {e}"}
    finally:
        # do NOT wait on a wedged probe thread; it ends via its own request
        # timeouts. shutdown(wait=False) returns immediately.
        ex.shutdown(wait=False)


def _detect_entrypoint(files):
    """
    Find the most likely runnable web-app entrypoint and its language.
    Supports any language whose runtime is installed (Python, Node.js, PHP,
    Ruby, Go today). Returns (rel_path, language) or (None, None).
    """
    from sandbox import runtime_detector as RT
    candidates = []  # (score, rel_path, language)

    for f in files:
        lang = f["language"]
        name = f["rel_path"].lower()
        base = os.path.basename(name)
        score = 0

        # only consider languages we can actually launch AND whose runtime exists
        if lang in ("tsx",):
            lang = "typescript"
        if not RT.is_available(lang):
            continue

        try:
            with open(f["path"], "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue

        if lang == "python":
            if base in ("app.py", "main.py", "server.py", "wsgi.py", "manage.py"):
                score += 5
            if "Flask(__name__)" in text or "FastAPI(" in text:
                score += 5
            if "app.run(" in text or "uvicorn" in text:
                score += 3
            if "if __name__" in text:
                score += 1
        elif lang in ("javascript", "typescript"):
            if base in ("server.js", "app.js", "index.js", "main.js",
                        "server.ts", "app.ts", "index.ts"):
                score += 5
            if "express(" in text or "require('express')" in text or 'require("express")' in text:
                score += 5
            if ".listen(" in text:
                score += 4
            if "createServer(" in text:
                score += 3
        elif lang == "php":
            if base in ("index.php", "app.php", "server.php", "router.php"):
                score += 5
            if "$_GET" in text or "$_POST" in text or "$_REQUEST" in text:
                score += 3
            if "header(" in text or "echo" in text or "json_encode(" in text:
                score += 2
        elif lang == "ruby":
            if base in ("app.rb", "server.rb", "config.ru", "main.rb"):
                score += 5
            if "Sinatra" in text or "require 'sinatra'" in text or "Rack" in text:
                score += 5
            if "get '/" in text or "post '/" in text or ".run" in text:
                score += 3
        elif lang == "go":
            if base in ("main.go", "server.go", "app.go"):
                score += 4
            if "package main" in text:
                score += 3
            if "http.ListenAndServe" in text or "http.HandleFunc" in text or "gin." in text:
                score += 5

        if score > 0:
            candidates.append((score, f["rel_path"], lang))

    candidates.sort(reverse=True, key=lambda c: c[0])
    if candidates:
        return candidates[0][1], candidates[0][2]
    return None, None


def classify_routes(routes):
    """Bucket routes by the probe they enable."""
    numeric_read = []   # GET returning a number (balance/stock)
    consume = []        # POST consuming amount/quantity
    id_routes = []      # GET with an id placeholder
    query_routes = []   # GET with a query string param
    file_routes = []    # GET reading a file path (path traversal)
    login_routes = []   # auth endpoints (SQL auth bypass)
    cmd_routes = []      # endpoints that run system commands
    template_routes = []  # endpoints that render templates (SSTI)
    redirect_routes = []  # endpoints that redirect (open redirect)
    fetch_routes = []     # endpoints that fetch a URL (SSRF)
    sensitive_routes = []  # sensitive actions (missing auth)

    for r in routes:
        methods = [m.upper() for m in r.get("methods", [])]
        path = r.get("path", "")
        plo = path.lower()
        if "GET" in methods and any(k in plo for k in ("balance", "wallet", "stock", "inventory", "credit")):
            numeric_read.append(r)
        if "POST" in methods and any(k in plo for k in ("pay", "checkout", "charge", "withdraw", "buy", "purchase", "reserve", "transfer", "spend")):
            consume.append(r)
        if "GET" in methods and re.search(r"<[^>]+>|:\w+|\{[^}]+\}", path):
            id_routes.append(r)
        if "GET" in methods and any(k in plo for k in ("search", "query", "find", "lookup", "filter")):
            query_routes.append(r)
        if any(k in plo for k in ("read", "file", "download", "view", "fetch", "load", "get_file", "static", "doc", "attachment")):
            file_routes.append(r)
        if any(k in plo for k in ("login", "signin", "auth", "session", "token", "logon")):
            login_routes.append(r)
        if any(k in plo for k in ("ping", "cmd", "exec", "run", "command", "shell", "lookup", "nslookup", "dns")):
            cmd_routes.append(r)
        if any(k in plo for k in ("render", "template", "preview", "greet", "hello", "msg", "message")):
            template_routes.append(r)
        if any(k in plo for k in ("go", "redirect", "next", "return", "out", "away", "link", "url")):
            redirect_routes.append(r)
        if any(k in plo for k in ("fetch", "proxy", "load", "import", "webhook", "callback")):
            fetch_routes.append(r)
        if any(k in plo for k in ("delete", "remove", "admin", "promote", "grant", "reset", "update", "transfer", "settings")):
            sensitive_routes.append(r)
    return (numeric_read, consume, id_routes, query_routes, file_routes, login_routes,
            cmd_routes, template_routes, redirect_routes, fetch_routes, sensitive_routes)


def run_dynamic(scan_result, sandbox_mgr, concurrency=20, budget=_DYNAMIC_BUDGET):
    """Run all applicable probes; return a list of probe-result dicts. The whole
    probe phase is bounded by `budget` seconds (and each probe by _PROBE_CAP), so
    the dynamic stage can never hang the run -- it always returns and the scan
    proceeds to reporting."""
    files = scan_result["files"]
    routes = scan_result["routes"]

    entry, entry_lang = _detect_entrypoint(files)
    if not entry:
        return {"ran": False, "reason": "no runnable web-app entrypoint detected "
                "(supported live runtimes: Python Flask/FastAPI, Node.js, PHP, Ruby, Go)"}

    (numeric_read, consume, id_routes, query_routes, file_routes, login_routes,
     cmd_routes, template_routes, redirect_routes, fetch_routes,
     sensitive_routes) = classify_routes(routes)

    if not any((numeric_read and consume, id_routes, query_routes, file_routes, login_routes,
                cmd_routes, template_routes, redirect_routes, fetch_routes, sensitive_routes)):
        return {"ran": False, "reason": "no endpoints matched any live probe shape"}

    results = []
    stage_start = time.time()
    deadline = stage_start + budget
    try:
        sandbox_copy = sandbox_mgr.create_copy(scan_result["target_dir"])
        # plant a sentinel file so path-traversal can be proven without relying
        # on system files existing
        try:
            import os as _os
            with open(_os.path.join(sandbox_copy, "lb_sentinel.txt"), "w") as _sf:
                _sf.write("LB_SENTINEL_a1b2c3")
        except Exception:
            pass
        proc, base_url = sandbox_mgr.start_for_language(sandbox_copy, entry_lang, entry)
    except Exception as e:
        return {"ran": False, "reason": f"could not launch target ({entry_lang}): {e}",
                "entrypoint": entry, "language": entry_lang}

    # Every probe below is wrapped in _capped(deadline, ...): it runs under a hard
    # per-probe cap AND the overall budget. _capped returns None once the budget
    # is exhausted -> we stop probing and finish the scan. A probe is NEVER
    # allowed to block the stage.
    def _add(res, ftype):
        if res is None:
            return False          # budget exhausted -> stop this probe group
        res["matched_finding_type"] = ftype
        results.append(res)
        return True
    try:
        if numeric_read and consume:
            _add(_capped(deadline, DT.probe_race_condition,
                         base_url, {"path": numeric_read[0]["path"]},
                         {"path": consume[0]["path"]}, concurrency=concurrency),
                 "Race Condition (TOCTOU)")

        for idr in id_routes[:3]:
            if not _add(_capped(deadline, DT.probe_idor, base_url, {"path": idr["path"]}),
                        "Insecure Direct Object Reference (IDOR)"):
                break

        for q in query_routes[:3]:
            if not _add(_capped(deadline, DT.probe_sql_injection, base_url, {"path": q["path"]}),
                        "SQL Injection"):
                break

        for lr in login_routes[:3]:
            if not _add(_capped(deadline, DT.probe_sql_auth_bypass, base_url, {"path": lr["path"]}),
                        "SQL Injection"):
                break

        for fr in file_routes[:3]:
            if not _add(_capped(deadline, DT.probe_path_traversal, base_url, {"path": fr["path"]}),
                        "Path Traversal"):
                break

        for cr in cmd_routes[:3]:
            if not _add(_capped(deadline, DT.probe_command_injection, base_url, {"path": cr["path"]}),
                        "OS Command Injection"):
                break

        for tr in template_routes[:3]:
            if not _add(_capped(deadline, DT.probe_ssti, base_url, {"path": tr["path"]}),
                        "Server-Side Template Injection"):
                break

        for rr in redirect_routes[:3]:
            if not _add(_capped(deadline, DT.probe_open_redirect, base_url, {"path": rr["path"]}),
                        "Open Redirect"):
                break

        for fr in fetch_routes[:3]:
            if not _add(_capped(deadline, DT.probe_ssrf, base_url, {"path": fr["path"]}),
                        "Server-Side Request Forgery (SSRF)"):
                break

        # CORS: probe a representative GET route
        cors_targets = (query_routes or id_routes or file_routes or numeric_read)[:1]
        for cr in cors_targets:
            if not _add(_capped(deadline, DT.probe_cors, base_url, {"path": cr["path"]}),
                        "Permissive CORS Configuration"):
                break

        for sr in sensitive_routes[:3]:
            if not _add(_capped(deadline, DT.probe_missing_auth, base_url,
                                {"path": sr["path"], "methods": sr.get("methods", ["GET"])}),
                        "Missing Authentication on Sensitive Action"):
                break
    finally:
        sandbox_mgr.stop_process(proc)

    return {"ran": True, "entrypoint": entry, "language": entry_lang, "results": results,
            "elapsed_s": round(time.time() - stage_start, 1), "budget_s": budget,
            "timed_out": time.time() >= deadline}
