"""
Concrete matchers
=================

Each class detects one vulnerability category across all supported languages
using the cross-language signal helpers. Severities follow a CWE-informed
default but are adjusted by confidence.

These are intentionally precision-tuned heuristics: they look for the
*co-occurrence* of the signals that define each flaw (e.g. a comparison guard
+ a blocking call + a state mutation + no lock = TOCTOU), not just a single
keyword. Race-condition findings on web endpoints are additionally promoted
to CONFIRMED by the dynamic exploitation stage.
"""

import re
from matchers.base import BaseMatcher, Finding
from matchers import signals as S


class RaceConditionMatcher(BaseMatcher):
    id = "race-condition"
    name = "Race Condition (TOCTOU)"
    cwe = "CWE-367"
    default_severity = "HIGH"

    def match(self, unit, context):
        src = unit["source"]
        lang = unit["language"]
        name = unit.get("name", "")

        if S.has_lock(src, lang):
            return []

        # constructors / initializers set up defaults; not a check-then-act.
        if name in ("__construct", "__init__", "constructor", "initialize",
                    "setUp", "configure", "register", "boot", "init"):
            return []

        # A TOCTOU race is only exploitable if concurrent execution can reach it
        # AND it mutates shared state.
        if not (_is_request_handler(unit) or _unit_has_route(unit, context)
                or _mutates_shared_state(unit)):
            return []

        # Require a GENUINE check-then-act pattern: a numeric balance/quota guard
        # decremented after a latency window, or a file-state check followed by a
        # file modification. This rejects string-building conditionals and socket
        # loops in network clients that merely co-locate a comparison, a blocking
        # call, and an assignment.
        pattern = S.detect_toctou(src, lang)
        if not pattern:
            return []

        blocking = S.has_blocking_call(src, lang)
        if pattern == "balance" and not blocking:
            return []   # a value race needs a real time-of-use gap (DB / IO / sleep)

        if pattern == "file":
            conf = 0.6
            window = "the gap between the file check and the file operation"
            guard_desc = "checks a file's state and then operates on the same path"
        else:
            conf = 0.78 if _looks_balance_like(unit) else 0.7
            window = f"a blocking call `{blocking}`"
            guard_desc = ("checks a value and then mutates the same value after "
                          f"{window}")
        return [self._finding(
            self, unit, severity="HIGH", confidence=conf,
            explanation=(
                f"`{unit['qualname']}` {guard_desc} without any visible lock or atomic "
                f"update. This is a Time-Of-Check-To-Time-Of-Use (TOCTOU) race condition."
            ),
            exploit_scenario=(
                "Race concurrent executions so they all pass the check before any commits, "
                "driving the resource past its intended state (or swap the file between check "
                "and use)."
            ),
            remediation=(
                "Hold a lock across the check-and-update, use an atomic DB operation "
                "(`UPDATE ... SET x = x - :n WHERE x >= :n`, `SELECT ... FOR UPDATE`), or "
                "operate on a file handle/descriptor rather than re-resolving the path."
            ),
            # Anchor: the comparison / guard line is the actual race check
            anchor_pattern=[r"\b(if|while|elseif|when)\s*\([^)]*(>=|<=|>|<|==)",
                           r"\b(?:balance|stock|count|quota|exists|file_exists|is_file)\b"],
        )]


class PriceManipulationMatcher(BaseMatcher):
    id = "price-manipulation"
    name = "Price / Quantity Manipulation"
    cwe = "CWE-840"
    default_severity = "HIGH"

    def match(self, unit, context):
        if not (_is_request_handler(unit) or _unit_has_route(unit, context)):
            return []
        src = S._strip_doc_and_comments(unit["source"], unit["language"])
        risky = S.numeric_params(unit.get("params", []))
        # also detect a price/amount/total variable read from client input
        # (require precise price-like names; avoid pagination 'total_items' etc.)
        client_price = re.findall(
            r"(\b(?:price|unit_price|amount|subtotal|grand_total|cost|fee|discount)\w*)\s*=\s*[^=\n]*"
            r"(?:request|req\.|params|\$_get|\$_post|get_json|\.json|\.form|\.args|\.body)",
            src, re.IGNORECASE)
        risky = list(risky) + [p for p in client_price if p not in risky]
        if not risky or S.has_bound_check(src):
            return []
        # the risky value must be used in arithmetic OR passed to a charge/total/save
        used = any(re.search(r"\b"+re.escape(p)+r"\b\s*[-+*/]|[-+*/]\s*\b"+re.escape(p)+r"\b", src) for p in risky) or \
               any(re.search(r"(charge|total|pay|debit|credit|save|amount|jsonify)\s*\([^)]*"+re.escape(p), src) for p in risky)
        if not used:
            return []
        return [self._finding(
            self, unit, severity="HIGH", confidence=0.55,
            explanation=(
                f"`{unit['qualname']}` uses client-controlled numeric parameter(s) "
                f"{', '.join(risky)} without a visible range/bounds check. Negative, zero, or "
                f"out-of-range values can corrupt pricing, totals, or balances."
            ),
            exploit_scenario=(
                f"Submit an out-of-range value for {', '.join(risky)} (e.g. negative quantity "
                f"or discount > 100%) to obtain free or negative-cost items."
            ),
            remediation=(
                "Validate and clamp every client-supplied numeric value server-side immediately "
                "on input; recompute money from trusted catalogue data, never from client totals."
            ),
            # Anchor: the first risky var assignment or arithmetic use
            anchor_pattern=[rf"\b{re.escape(p)}\b\s*[-+*/]" for p in risky[:1]] +
                           [rf"\b{re.escape(p)}\b\s*=" for p in risky[:1]],
        )]


class IDORMatcher(BaseMatcher):
    id = "idor"
    name = "Insecure Direct Object Reference (IDOR)"
    cwe = "CWE-639"
    default_severity = "HIGH"

    # real data-access sinks (a fetch BY id), not the generic word "get"
    _FETCH = (".get(", ".find(", ".find_by", ".findone", ".findbyid", ".load(",
              ".fetch(", ".query(", "find_by_id", "getobjectbyid", "objects.get(",
              ".filter(", ".filter_by(", ".get_or_404(", "session.get(", "db.",
              "repository.", "->find(", "::find(", "where(", "select ", "from ")

    def match(self, unit, context):
        src = unit["source"]
        ids = S.id_params(unit.get("params", []))
        if not ids:
            return []

        # 1) the function must actually be a request handler (reachable by a
        #    remote user). Otherwise an `id` parameter is just an internal arg.
        if not (_is_request_handler(unit) or _unit_has_route(unit, context)):
            return []

        # 2) it must perform a real object fetch keyed off that id
        body = S._strip_doc_and_comments(src, unit["language"]).lower()
        if not any(tok in body for tok in self._FETCH):
            return []
        # the id parameter must actually be USED in the body
        if not any(re.search(rf"\b{re.escape(i)}\b", body) for i in ids):
            return []

        # 3) no ownership / authorization check present (consider decorators too,
        #    e.g. a handler guarded only by @login_required / @require_owner).
        if S.has_ownership_check(src + "\n" + unit.get("decorators", "")):
            return []

        return [self._finding(
            self, unit, severity="HIGH", confidence=0.5,
            explanation=(
                f"`{unit['qualname']}` looks up an object using client-supplied id parameter(s) "
                f"{', '.join(ids)} without a visible ownership/authorization check. A user may be "
                f"able to access another user's records by changing the id."
            ),
            exploit_scenario=(
                f"Authenticate as user A, then request a resource with user B's id in "
                f"{', '.join(ids)} to read or modify B's data."
            ),
            remediation=(
                "After loading the object, verify it belongs to the authenticated principal "
                "(e.g. `obj.owner_id == current_user.id`); prefer deriving the owner from the "
                "session over trusting a client id."
            ),
            # Anchor: the first .find/.get/.filter/.where call (the actual fetch)
            anchor_pattern=[
                r"\.get\s*\(", r"\.find\s*\(", r"\.fetch\s*\(",
                r"\.query\s*\(", r"\.filter\s*\(", r"where\s*\(",
                r"select\s+", r"from\s+", r"->find\s*\(",
            ],
        )]


class SQLInjectionMatcher(BaseMatcher):
    id = "sql-injection"
    name = "SQL Injection"
    cwe = "CWE-89"
    default_severity = "CRITICAL"

    def match(self, unit, context):
        src = unit["source"]
        lang = unit["language"]
        sink = S.has_sql_sink(src, lang)
        concat = S.looks_concatenated_sql(src, lang)
        if concat and not S.is_parameterized(src) and not S.concat_input_is_cast(src, lang) \
                and not S.sql_concat_input_is_safe(src, lang):
            # Zero-FP gate: only flag when attacker-controllable input is actually
            # visible reaching this unit. Concatenated SQL built purely from
            # internal values (framework table identifiers like {$wpdb->posts},
            # already-sanitised fragments, integer ID lists) is not injectable.
            # Cross-function tainted-parameter flows are covered by the taint engine.
            if not S.has_untrusted_source(src, lang) and \
               not S.param_flows_into_sql(src, lang, unit.get("params", [])):
                return []
            return [self._finding(
                self, unit, severity="CRITICAL", confidence=0.6,
                explanation=(
                    f"`{unit['qualname']}` builds a SQL statement via string concatenation/"
                    f"interpolation"
                    f"{' and passes it to a query sink (`' + sink + '`)' if sink else ''} without "
                    f"parameterization. This is a SQL injection risk."
                ),
                exploit_scenario=(
                    "Supply input containing SQL metacharacters (e.g. `' OR '1'='1`) to alter the "
                    "query and read/modify unintended data."
                ),
                remediation=(
                    "Use parameterized queries / prepared statements with bound parameters; never "
                    "concatenate untrusted input into SQL."
                ),
                anchor_pattern=[
                    r"(?:select|insert|update|delete)\b.*[+%]",
                    r"[+%].*(?:select|insert|update|delete)\b",
                    r"\b(?:execute|query|cursor)\s*\(",
                ],
                anchor_flags=re.IGNORECASE,
            )]
        return []


class BrokenAuthMatcher(BaseMatcher):
    id = "broken-auth"
    name = "Broken Authorization (client-trusted role)"
    cwe = "CWE-602"
    default_severity = "HIGH"

    def match(self, unit, context):
        src = unit["source"]
        lang = unit["language"]
        if not (_is_request_handler(unit) or _unit_has_route(unit, context)):
            return []
        if S.reads_client_role(src, lang):
            # If the handler performs a capability / nonce / authentication check,
            # the client-supplied role is validated server-side and this is not a
            # trust-the-client vulnerability (e.g. WordPress edit_user gated by
            # current_user_can('promote_users') + check_admin_referer).
            if re.search(
                    r"current_user_can|map_meta_cap|check_admin_referer|wp_verify_nonce"
                    r"|check_ajax_referer|is_user_logged_in|user_can\s*\(|author_can"
                    r"|->can\s*\(|\bauthorize\b|permission_callback|@login_required"
                    r"|requires?_auth|hasRole|hasAuthority|@PreAuthorize|Gate::",
                    src, re.IGNORECASE):
                return []
            # If the client role is used ONLY as an array-lookup KEY (a bounded
            # dictionary access like $roles[$_REQUEST['role']] to fetch a role's
            # display data) and never flows into a gating conditional or a
            # privilege-setting assignment, it is a data lookup, not a trusted
            # authorization decision -> not CWE-602.
            cns = re.sub(r"#.*|//.*", "", src)
            role_as_key = re.search(
                r"\[\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"][\w-]*"
                r"(?:role|is_admin|permission|privilege|user_type)"
                r"|request\.\w+\s*(?:\[\s*['\"]|\.get\s*\(\s*['\"])[\w-]*(?:role|is_admin|permission)"
                r"|params\[\s*:?\s*['\"]?[\w-]*(?:role|is_admin))",
                cns, re.IGNORECASE)
            role_gates = re.search(
                r"(?:if|elseif|while|switch|when)\s*\([^)]*"
                r"(?:role|is_admin|is_superuser|privilege|permission|user_type|access_level)"
                r"|(?:role|is_admin|is_superuser|privilege|access_level)\s*(?:==|===|!==|!=)"
                r"|->\s*(?:role|is_admin|setRole|set_role)\s*=|->\s*set_role\s*\("
                r"|(?:grant|promote|add_role|assign_role|set_role|add_cap)\s*\(",
                cns, re.IGNORECASE)
            if role_as_key and not role_gates:
                return []
            return [self._finding(
                self, unit, severity="HIGH", confidence=0.55,
                explanation=(
                    f"`{unit['qualname']}` appears to read a role/privilege flag from client input "
                    f"and use it to gate behaviour. Trusting client-supplied roles allows trivial "
                    f"privilege escalation."
                ),
                exploit_scenario=(
                    "Send a request with `is_admin=true` (or an elevated `role`) in the body, "
                    "cookie, or header to gain privileged access."
                ),
                remediation=(
                    "Resolve the principal's role server-side from the authenticated session or "
                    "database; never trust a role value supplied by the client."
                ),
                anchor_pattern=[
                    r"\b(?:role|is_admin|is_superuser|privilege|permission|user_type|access_level)\b\s*(?:==|===|!=|!==|=)",
                    r"\b(?:role|is_admin|is_superuser|privilege|permission|user_type|access_level)\b",
                ],
                anchor_flags=re.IGNORECASE,
            )]
        return []


class WeakAuthMatcher(BaseMatcher):
    """Broken Authentication (CWE-287): the application authenticates by comparing
    client-supplied input against a STATIC secret/key/password -- typically read
    from a query string or header. This is weak because (1) secrets in query
    strings leak into logs, proxies and browser history, (2) a single static
    credential isn't per-user and can't be revoked individually, and (3) `==`
    comparison is timing-attack prone.

    To avoid false positives this fires ONLY when ALL hold:
      - a value is read from client input (request/query/header/args), AND
      - it is compared with `==`/`!=`/equals against an auth-ish operand
        (a constant secret, an env secret, or a hardcoded key), AND
      - the surrounding context is authentication (key/token/password/admin/auth),
      - and there is NO proper auth mechanism already in place
        (session/JWT verify/oauth/hmac/bcrypt/compare_digest).
    """
    id = "weak-auth"
    name = "Broken Authentication (static credential)"
    cwe = "CWE-287"
    default_severity = "HIGH"

    _CLIENT_READ = (r"request\.args", r"request\.query", r"request\.values",
                    r"request\.headers", r"request\.get", r"\.args\.get",
                    r"\.query\.get", r"req\.query", r"req\.headers",
                    r"\$_get", r"\$_request", r"getParameter\(", r"query\[")
    _AUTH_WORDS = ("key", "token", "password", "passwd", "secret", "auth",
                   "admin", "apikey", "api_key", "access", "credential")
    _PROPER_AUTH = ("session", "jwt.decode", "verify_jwt", "oauth", "hmac",
                    "compare_digest", "check_password_hash", "bcrypt", "verify(",
                    "login_required", "@requires_auth", "current_user",
                    "authenticate(", "passport", "verify_token")

    def match(self, unit, context):
        import re
        if not (_is_request_handler(unit) or _unit_has_route(unit, context)):
            return []
        src = S._strip_doc_and_comments(unit["source"], unit["language"])
        low = src.lower()

        # (1) must read from client input
        reads_client = any(re.search(p, src, re.IGNORECASE) for p in self._CLIENT_READ)
        if not reads_client:
            return []

        # find the variable(s) read from client input
        client_vars = re.findall(
            r"(\w+)\s*=\s*[^=\n]*(?:request\.|req\.|\.args|\.query|\.values|\.headers|"
            r"\$_get|\$_request|getparameter)",
            src, re.IGNORECASE)
        if not client_vars:
            return []

        # (2) one of those client vars must be compared with == / != / .equals
        compared = False
        compared_var = None
        for v in client_vars:
            if re.search(r"\b" + re.escape(v) + r"\s*(==|!=)\s*\w", src) or \
               re.search(r"\w+\s*(==|!=)\s*\b" + re.escape(v) + r"\b", src) or \
               re.search(r"\b" + re.escape(v) + r"\b\.equals\(", src) or \
               re.search(r"\bequals\(\s*" + re.escape(v) + r"\b", src):
                compared = True
                compared_var = v
                break
        if not compared:
            return []

        # (3) the comparison must be in an authentication context
        if not any(w in low for w in self._AUTH_WORDS):
            return []
        # the compared variable itself, or the constant it's compared to, should
        # look auth-related (key/token/secret/password/api_key) -- avoids firing
        # on `if status == expected` style non-auth equality.
        cmp_context = compared_var.lower() if compared_var else ""
        line_with_cmp = ""
        for ln in src.split("\n"):
            if compared_var and re.search(r"\b" + re.escape(compared_var) + r"\b\s*(==|!=)", ln):
                line_with_cmp = ln.lower()
                break
        if not any(w in (cmp_context + " " + line_with_cmp) for w in self._AUTH_WORDS):
            return []

        # (4) NOT already using a proper auth mechanism
        if any(p in low for p in self._PROPER_AUTH):
            return []

        # prefer to flag the query-string case as it's the most dangerous, but
        # header-based static keys are also weak.
        via_query = bool(re.search(r"(\.args|\.query|\.values|\$_get|query\[|getparameter)", src, re.IGNORECASE))
        where = "query string" if via_query else "client request"
        return [self._finding(
            self, unit, severity="HIGH", confidence=0.6,
            explanation=(
                f"`{unit['qualname']}` authenticates by comparing a client-supplied value "
                f"(from the {where}) against a static secret/key. Static credentials passed in the "
                f"{where} leak into logs, proxies and browser history, aren't per-user, and the "
                f"`==` check is timing-attack prone."
            ),
            exploit_scenario=(
                "An attacker who obtains the key from a log, referrer header, or shared URL gains "
                "full access; the single static credential cannot be revoked per user."
            ),
            remediation=(
                "Use a real authentication mechanism: per-user credentials with a server-side "
                "session or signed token (JWT), send secrets in headers (Authorization) not the "
                "query string, store only hashed secrets, and compare with a constant-time function "
                "like hmac.compare_digest."
            ),
            anchor_pattern=[
                rf"\b{re.escape(compared_var)}\b\s*(?:==|!=|\.equals\()" if compared_var else r"==",
                r"==\s*\w",
            ],
        )]


class NegativeQuantityMatcher(BaseMatcher):
    id = "negative-quantity"
    name = "Negative / Zero Quantity"
    cwe = "CWE-840"
    default_severity = "MEDIUM"

    def match(self, unit, context):
        if not (_is_request_handler(unit) or _unit_has_route(unit, context)):
            return []
        src = S._strip_doc_and_comments(unit["source"], unit["language"])
        import re
        params = unit.get("params", [])
        # precise quantity names only (avoid 'count'/'amount'/'units' which appear
        # as ordinary parameter names in non-commerce code and cause false hits).
        qty_kw = ("qty", "quantity", "num_items", "item_count", "order_qty")
        # a bare parameter named like a quantity counts ONLY if the function also
        # reads client input (otherwise an internal helper with a param named
        # 'quantity' would wrongly trip).
        reads_client = bool(re.search(
            r"(request\.|req\.body|req\.query|\.args\.get|\.form\.get|\.get_json|"
            r"\$_get|\$_post|params\[)", src, re.IGNORECASE))
        qty = [p for p in params if any(k == p.lower() for k in qty_kw)] if reads_client else []
        # also detect a quantity-like variable read from client input
        client_qty = re.findall(
            r"(\b(?:qty|quantity|num_items|item_count|order_qty)\w*)\s*=\s*[^=\n]*"
            r"(?:request|req\.|params|\$_get|\$_post|get_json|\.json|\.form|\.args|\.body)",
            src, re.IGNORECASE)
        qty = qty + [q for q in client_qty if q not in qty]
        if not qty:
            return []
        if S.has_bound_check(src):
            return []
        # must be genuinely used in arithmetic (NOT merely present -- a quantity
        # that is only logged or echoed is not a manipulation risk).
        arith = bool(re.search(r"[-+*/]\s*\w*(qty|quantity|num_items|item_count|order_qty)", src, re.IGNORECASE)) or \
                bool(re.search(r"(qty|quantity|num_items|item_count|order_qty)\w*\s*[-+*/]", src, re.IGNORECASE)) or \
                any(re.search(r"(charge|total|pay|debit|credit|save|price|subtotal|stock|balance|jsonify)\s*\([^)]*"
                              + re.escape(p), src, re.IGNORECASE) for p in qty)
        if not arith:
            return []
        return [self._finding(
            self, unit, severity="MEDIUM", confidence=0.45,
            explanation=(
                f"`{unit['qualname']}` uses quantity parameter(s) {', '.join(qty)} in arithmetic "
                f"without checking that the value is positive. Negative quantities can invert "
                f"balance/stock calculations."
            ),
            exploit_scenario=(
                f"Submit a negative value for {', '.join(qty)} to credit your own balance or "
                f"manipulate inventory."
            ),
            remediation="Reject non-positive quantities (and enforce a sane upper bound) on input.",
            anchor_pattern=[
                rf"\b{re.escape(p)}\b\s*[-+*/]" for p in qty[:1]
            ] + [
                r"\b(?:qty|quantity|num_items|item_count|order_qty)\w*\s*[-+*/]",
            ],
            anchor_flags=re.IGNORECASE,
        )]


class HardcodedSecretMatcher(BaseMatcher):
    id = "hardcoded-secret"
    name = "Hardcoded Secret / Credential"
    cwe = "CWE-798"
    default_severity = "HIGH"

    _PATTERNS = [
        (r"(?i)(api[_-]?key|secret|passwd|password|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]", "credential assignment"),
        (r"AKIA[0-9A-Z]{16}", "AWS access key"),
        (r"(?i)bearer\s+[a-z0-9\-_\.]{20,}", "bearer token"),
        (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "private key"),
        # Unambiguous provider key formats: the prefix + length makes these real
        # secrets, never placeholders. Safe to flag wherever they appear.
        (r"\bsk_live_[0-9a-zA-Z]{20,}", "Stripe live secret key"),
        (r"\bsk_test_[0-9a-zA-Z]{20,}", "Stripe test secret key"),
        (r"\bghp_[0-9A-Za-z]{36}\b", "GitHub personal access token"),
        (r"\bgithub_pat_[0-9A-Za-z_]{50,}", "GitHub fine-grained token"),
        (r"\bglpat-[0-9A-Za-z_\-]{20,}", "GitLab personal access token"),
        (r"\bAIza[0-9A-Za-z_\-]{35}\b", "Google API key"),
        (r"\bxox[baprs]-[0-9A-Za-z\-]{10,}", "Slack token"),
        #  database/connection-string URLs with embedded credentials.
        # Matches: postgresql://user:password@host/db, redis://:password@host,
        # mysql://user:pass@host, mongodb://user:pass@host, amqp://user:pass@host
        # The key signal is "scheme://[user][:pass]@" -- the @ before the host
        # proves credentials are embedded.
        (r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb|redis|amqp|amqps|mssql)://[^\s\"'/@]*:[^\s\"'/@]+@[^\s\"'/]+", "database connection string with credentials"),
        #  generic URL with user:pass@ -- catches http://admin:pass@host too
        (r"(?i)\bhttps?://[a-z0-9_\-]+:[a-z0-9_\-]{4,}@[a-z0-9.\-]+", "URL with embedded credentials"),
        #  DB_URL / DATABASE_URL / REDIS_URL assignments with a URL value
        (r"(?i)\b(?:db_url|database_url|redis_url|mongo_url|amqp_url|connection_string|dsn)\s*[:=]\s*['\"][^'\"]{10,}['\"]", "connection string assignment"),
    ]

    def match(self, unit, context):
        import re
        src = unit["source"]
        for pattern, label in self._PATTERNS:
            for m in re.finditer(pattern, src):
                matched = m.group(0)
                # ignore obvious placeholders
                window = src[max(0, m.start() - 5):m.end() + 60]
                if re.search(r"(?i)(your[_-]?|example|placeholder|xxxx|<.*>|changeme)", window):
                    continue
                # the captured value itself
                val_m = re.search(r"['\"]([^'\"]+)['\"]", matched)
                value = val_m.group(1) if val_m else ""
                # FALSE-POSITIVE GUARD 1: a template placeholder like {password},
                # ${x}, %s, :name is NOT a hardcoded secret -- it's interpolation.
                if re.search(r"[\{\}\$%]|^\s*:\w+\s*$", value) or value.startswith((":", "%")):
                    continue
                line = src[src.rfind("\n", 0, m.start()) + 1: src.find("\n", m.end())]
                # FALSE-POSITIVE GUARD 2: the match sits inside a longer string
                # literal (e.g. an f-string SQL query "... AND password='{x}'").
                # If the line contains a SQL keyword or is an f-string, skip.
                if re.search(r"(?i)\b(select|insert|update|delete|where|from)\b", line) or \
                   re.search(r'f["\']', line):
                    continue
                # FALSE-POSITIVE GUARD 3: value is READ from request/env/config or
                # a function call, not a literal assigned secret.
                if re.search(r"=\s*[A-Za-z_][\w\.]*\s*(\(|\[)", line):
                    continue
                if re.search(r"(?i)(request\.|getenv|environ|os\.environ|config\[|\.get\(|input\(|"
                             r"argv|prompt|getpass)", line):
                    continue
                return [self._finding(
                    self, unit, severity="HIGH", confidence=0.6,
                    explanation=(
                        f"`{unit['qualname']}` contains what looks like a hardcoded {label}. "
                        f"Secrets in source code leak through version control and backups."
                    ),
                    exploit_scenario="Anyone with read access to the repository obtains the secret.",
                    remediation="Move secrets to environment variables or a secrets manager; rotate the exposed value.",
                    anchor_pattern=pattern,
                )]
        return []


class MissingRateLimitMatcher(BaseMatcher):
    id = "missing-rate-limit"
    name = "Sensitive Action Without Rate Limiting"
    cwe = "CWE-307"
    default_severity = "MEDIUM"

    def match(self, unit, context):
        if not (_is_request_handler(unit) or _unit_has_route(unit, context)):
            return []
        name = unit.get("name", "").lower()
        # include decorators -- rate limiting is very often applied as a decorator
        # (@limiter.limit(...), @ratelimit(...)) which is NOT in the function body.
        src = (S._strip_doc_and_comments(unit["source"], unit["language"])
               + "\n" + unit.get("decorators", "")).lower()
        sensitive = any(k in name for k in ("login", "authenticate", "signin", "log_in",
                                            "reset_password", "forgot_password", "send_otp",
                                            "verify_otp", "send_code", "verify_code"))
        if not sensitive:
            return []
        # Skip framework AUTH FILTER CALLBACKS: a function whose first parameter is
        # the already-resolved user/result/value (e.g. WordPress
        # wp_authenticate_cookie($user, $username, $password)) runs *inside* the
        # authentication pipeline, not at the public brute-forceable boundary,
        # and merely returns the filtered value. Rate limiting belongs on the
        # form/endpoint, so flagging the callback is a false positive.
        params = unit.get("params", []) or []
        if params:
            first = str(params[0]).lstrip("$&*").strip().lower()
            if first in ("user", "result", "value", "$user", "filtered", "wp_user"):
                return []
        has_limit = any(t in src for t in ("ratelimit", "rate_limit", "throttle", "limiter",
                                            "attempts", "lockout", "429", "too many requests",
                                            "_lb_rl", "remote_addr"))
        if has_limit:
            return []
        # FALSE-POSITIVE GUARD: only flag when the handler actually performs an
        # authentication check (compares a password/credential or queries a user
        # table). A route merely *named* login with no real auth logic is not
        # strong enough evidence to warrant a finding.
        does_auth = any(t in src for t in (
            "password", "passwd", "check_password", "verify_password", "bcrypt",
            "compare_digest", "hashlib", "select", "fetchone", "fetchall",
            "authenticate", "credential")) 
        if not does_auth:
            return []
        return [self._finding(
            self, unit, severity="MEDIUM", confidence=0.4,
            explanation=(
                f"`{unit['qualname']}` performs a sensitive auth-related action but shows no "
                f"rate limiting / attempt throttling, enabling brute force or OTP-flooding."
            ),
            exploit_scenario="Automate thousands of attempts against this endpoint to brute force credentials or OTPs.",
            remediation="Add per-account and per-IP rate limiting / exponential backoff / lockout.",
            anchor_pattern=[
                r"\b(?:password|passwd|check_password|verify_password|bcrypt|compare_digest|hashlib)\b",
                r"\b(?:select|fetchone|fetchall|authenticate|credential)\b",
            ],
            anchor_flags=re.IGNORECASE,
        )]


ALL_MATCHERS = [
    RaceConditionMatcher(),
    PriceManipulationMatcher(),
    IDORMatcher(),
    SQLInjectionMatcher(),
    BrokenAuthMatcher(),
    WeakAuthMatcher(),
    NegativeQuantityMatcher(),
    HardcodedSecretMatcher(),
    MissingRateLimitMatcher(),
]

# Append the extended catalogue (OS command injection, path traversal, SSTI,
# weak crypto, open redirect, mass assignment, XXE, insecure deserialization,
# missing auth, debug mode, CORS, JWT). Kept in a separate module so the core
# stays readable and the catalogue is easy to grow.
try:
    from matchers.extended import EXTENDED_MATCHERS
    ALL_MATCHERS = ALL_MATCHERS + EXTENDED_MATCHERS
except Exception:  # pragma: no cover
    pass


def _looks_balance_like(unit):
    src = unit["source"].lower()
    return any(k in src for k in ("balance", "stock", "inventory", "credit", "quantity", "count"))


# ----------------------------------------------------------------------
# Reachability helpers: is this code actually exposed to a remote user?
# A flaw like IDOR / broken-auth / SSRF only matters on a request handler,
# not on an arbitrary internal helper function.
# ----------------------------------------------------------------------
_REQUEST_SIGNALS = (
    "request.", "req.", "self.request", "request.args", "request.form",
    "request.json", "request.get_json", "request.params", "request.values",
    "$_get", "$_post", "$_request", "$_cookie",
    "@app.route", "@app.get", "@app.post", "@app.put", "@app.delete", "@app.patch",
    "@router.", "@blueprint", "@bp.route", "@get(", "@post(", "@put(", "@delete(",
    "@requestmapping", "@getmapping", "@postmapping", "@deletemapping",
    "httpservletrequest", "gin.context", "*gin.context", "echo.context",
    "http.responsewriter", "*http.request", "res.json(", "res.send(",
    "jsonify(", "make_response(",
)


def _guard_and_mutation_share_var(source):
    """
    A genuine TOCTOU race checks a resource and then mutates THE SAME resource
    (e.g. `if balance >= amount: ... balance -= amount`). This requires that at
    least one variable appearing in a comparison also appears as the target of
    a mutation. This single check eliminates the bulk of false positives where
    a function merely happens to contain an unrelated comparison and an
    unrelated assignment.
    """
    code = S._strip_doc_and_comments(source, "")
    # normalise arrows/access so they don't pollute the scan, but KEEP the
    # comparison operators (collapse >=,<= to >,< so one regex catches them).
    c = code.replace("=>", "  ").replace("->", ".")
    c = c.replace(">=", ">").replace("<=", "<").replace("==", "  ").replace("!=", "  ")

    compared = set()
    for m in re.finditer(r"([A-Za-z_$][\w$\.\[\]'\"]*|\d[\w.]*)\s*[<>]\s*"
                         r"([A-Za-z_$][\w$\.\[\]'\"]*|\d[\w.]*)", c):
        for g in (m.group(1), m.group(2)):
            if g and not g[0].isdigit():     # only variable operands, not literals
                compared.add(_base_var(g))
    if not compared:
        return False

    # variables that are mutated (compound assignment, or plain = on an attr/var)
    mutated = set()
    for m in re.finditer(r"([A-Za-z_$][\w$\.\[\]'\"]*)\s*([-+*/]=|=)(?!=)", code):
        mutated.add(_base_var(m.group(1)))
    # ALSO: variables passed into a setter / persistence call are "mutated"
    # (e.g. set_balance(bal - amount) writes back the resource named by `bal`).
    for m in re.finditer(r"(?:set_\w+|\.save|\.update|\.decrement|\.increment|"
                         r"\.insert|\.create)\s*\(([^)]*)\)", code, re.IGNORECASE):
        for var in re.findall(r"[A-Za-z_]\w*", m.group(1)):
            mutated.add(var.lower())

    return bool(compared & mutated)


def _base_var(token):
    """Reduce 'this.balance' / '$this->balance' / 'obj[\"x\"]' to a base name
    for comparison ('balance' / 'x')."""
    t = token.strip().strip("$")
    t = t.replace("$", "")
    # take the last attribute/index segment
    t = re.split(r"\.|->|\[", t)[-1]
    t = t.strip("'\"]) ")
    return t.lower()


def _mutates_shared_state(unit) -> bool:
    """
    True if the unit mutates state that is shared across concurrent calls:
    an instance attribute (self./this./$this->), a class/static field, or --
    for a method inside a class -- a bare field that is not a local or param.
    A function that only mutates its own locals can't have a cross-request race.
    """
    code = S._strip_doc_and_comments(unit.get("source", ""), unit.get("language", ""))
    explicit = [
        r"self\.\w+\s*[-+*/]?=[^=]",
        r"this\.\w+\s*[-+*/]?=[^=]",
        r"\$this->\w+\s*[-+*/]?=[^=]",
        r"\b\w+\.\w+\s*[-+*/]=[^=]",         # receiver.field op= (go/java)
        r"@\w+\s*[-+*/]?=[^=]",              # ruby ivar
        r"\w+\[[^\]]+\]\s*[-+*/]?=[^=]",     # shared dict/map write
    ]
    if any(re.search(p, code) for p in explicit):
        return True

    # method inside a class that mutates a bare identifier which is NOT declared
    # locally and NOT a parameter -> almost certainly a class field (shared).
    if unit.get("class_name"):
        params = set(unit.get("params", []))
        # find compound/assignment targets like `balance -= x` or `stock = ...`
        for m in re.finditer(r"\b([a-zA-Z_]\w*)\s*([-+*/]?=)[^=]", code):
            name = m.group(1)
            if name in params:
                continue
            # is it declared locally in this function? (var/let/const/type decl, or `name =` first-assignment with a type)
            declared_local = re.search(
                r"\b(?:var|let|const|int|double|float|long|String|boolean|auto)\s+" + re.escape(name) + r"\b", code
            ) or re.search(r"\b" + re.escape(name) + r"\s*:=", code)  # go :=
            if not declared_local:
                return True
    return False


def _is_request_handler(unit) -> bool:
    # a function linked to an HTTP route decorator is definitely a handler,
    # even if its body doesn't reference request.* directly (the danger comes
    # from its path parameters, e.g. /user/<user_id>)
    if unit.get("is_route_handler"):
        return True
    body = unit.get("source", "")
    # strip comments/docstrings so prose doesn't count
    code = S._strip_doc_and_comments(body, unit.get("language", "")).lower()
    return any(sig in code for sig in _REQUEST_SIGNALS)


def _unit_has_route(unit, context) -> bool:
    """True if a discovered route maps to this unit (handler)."""
    try:
        qual = unit.get("qualname")
        for r in getattr(context, "routes", []) or []:
            if r.get("handler") and r["handler"] == qual and r.get("file") == unit.get("file"):
                return True
    except Exception:
        pass
    return False
