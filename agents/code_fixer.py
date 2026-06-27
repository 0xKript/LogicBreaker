"""
In-file code fixer
==================

Applies REAL, in-place fixes to the actual source file for each vulnerability
class -- not recommendations, not comments. After a fix is applied the same
detector must no longer flag the code (verified by re-running the matcher on
the patched source).

The philosophy of the tool is: find -> exploit -> ASK -> fix -> re-test, and a
re-scan of a fixed file must report the vulnerability as CLOSED.

Each fixer returns (patched_source, explanation) or (None, reason). A fixer is
only considered successful if, after applying it, the corresponding matcher no
longer fires on the patched function.
"""

import re


# Self-contained restricted unpickler, injected at function-body scope by the
# textual deserialization fixer when only a function slice is available (the
# LibCST path injects an equivalent class at module scope). It blocks every
# non-builtin global, so __reduce__/os.system RCE gadgets raise instead of run.
_PICKLE_LOCAL_GUARD = (
    "import io as _lb_io, pickle as _lb_pickle\n"
    "class _LBRestrictedUnpickler(_lb_pickle.Unpickler):\n"
    "    _ALLOWED = {(\"builtins\", n) for n in (\n"
    "        \"list\", \"dict\", \"tuple\", \"set\", \"frozenset\", \"str\", \"bytes\",\n"
    "        \"bytearray\", \"int\", \"float\", \"bool\", \"complex\", \"NoneType\")}\n"
    "    def find_class(self, module, name):\n"
    "        if (module, name) in self._ALLOWED:\n"
    "            return super().find_class(module, name)\n"
    "        raise _lb_pickle.UnpicklingError(\n"
    "            f\"blocked unsafe pickle global: {module}.{name}\")\n"
    "def _lb_safe_loads(data):\n"
    "    return _LBRestrictedUnpickler(_lb_io.BytesIO(data)).load()\n"
    "def _lb_safe_load(fp):\n"
    "    return _LBRestrictedUnpickler(fp).load()"
)


# Validator for user-supplied command arguments (extra hardening on top of the
# shell-removal fix): rejects option-injection (leading '-') and anything outside
# a hostname/IP/path charset, so a user value can't be reinterpreted as a flag or
# smuggle shell metacharacters. Injected at module scope by the command fixers.
_CMD_ARG_HELPER = (
    "import re as _lb_re\n"
    "def _lb_safe_cmd_arg(v):\n"
    '    """Reject option-injection and out-of-charset command arguments."""\n'
    "    v = str(v)\n"
    '    if not v or v[0] == "-" or not _lb_re.fullmatch(r"[A-Za-z0-9._:/-]+", v):\n'
    '        raise ValueError("rejected unsafe command argument: %r" % (v,))\n'
    "    return v"
)


# Safe replacement for eval()/exec() of attacker-influenced input. eval() is
# redirected to ast.literal_eval (which parses ONLY Python literals -- numbers,
# strings, tuples/lists/dicts of literals -- and can never call a function or run
# code). exec() has no safe equivalent (it runs arbitrary statements), so it is
# routed to a guard that refuses. Both close the code-injection sink completely.
_SAFE_EVAL_HELPER = (
    "import ast as _lb_ast\n"
    "def _lb_safe_eval(expr):\n"
    '    """Parse ONLY literals via ast.literal_eval; never runs code."""\n'
    "    return _lb_ast.literal_eval(expr)\n"
    "def _lb_no_exec(code, *a, **k):\n"
    '    """Dynamic code execution is never safe -- refuse instead of running it."""\n'
    '    raise ValueError(\"blocked dynamic code execution (code injection)\")'
)


# Secure drop-in for the non-cryptographic `random` module: secrets.SystemRandom
# exposes the SAME API (random/randint/randrange/choice/getrandbits/...) but is a
# CSPRNG, so generated tokens/values become unpredictable. Injected at module
# scope; call sites have `random.` rewritten to `_lb_secure_rng.`.
_SECURE_RNG_HELPER = (
    "import secrets as _lb_secrets\n"
    "_lb_secure_rng = _lb_secrets.SystemRandom()"
)


def _insert_module_helper(src, marker, block):
    """Insert a module-level helper `block` after the leading __future__/docstring/
    import region (and before the first def/class/decorator/statement), unless
    `marker` already appears in `src`. Keeps the result syntactically valid."""
    if marker in src:
        return src
    lines = src.split("\n")
    idx, in_doc, doc_q = 0, False, None
    for i, ln in enumerate(lines):
        s = ln.strip()
        if in_doc:
            idx = i + 1
            if doc_q in s:
                in_doc = False
            continue
        if s.startswith(('"""', "'''")):
            doc_q = s[:3]
            # single-line docstring?
            if not (len(s) >= 6 and s.endswith(doc_q)):
                in_doc = True
            idx = i + 1
            continue
        if s == "" or s.startswith("#") or s.startswith("import ") or s.startswith("from "):
            idx = i + 1
            continue
        break
    return "\n".join(lines[:idx] + [block, "", ""] + lines[idx:])


def _php_prepare_handle(full_src):
    """Choose the right prepare() handle based on what the file uses."""
    if "$wpdb" in full_src:
        return "$wpdb"
    for h in ("$pdo", "$this->pdo", "$this->db", "$db", "$conn", "$dbh", "$mysqli"):
        if h in full_src:
            return h
    return "$pdo"


def _is_sql_fragment_var(varname):
    """A variable that holds a SQL *fragment* (a clause), not a single value,
    cannot be safely turned into a bound parameter. We detect these by common
    naming so we DON'T produce a broken 'fix'."""
    n = varname.lower().lstrip("$")
    return any(k in n for k in ("where", "sql", "query", "join", "clause", "orderby",
                                "groupby", "limit", "having", "fields", "cols", "from"))


def _php_parameterize(assign, expr, handle='$pdo'):
    """Turn `$x = "..." . $var . "..."` into a $wpdb->prepare/PDO prepared call.
    Returns the original text unchanged if any concatenated variable is a SQL
    fragment (unsafe to bind)."""
    pieces = _split_top_level_dot(expr)
    sql_parts, params = [], []
    for p in pieces:
        p = p.strip()
        sm = re.match(r'^"([^"]*)"$', p) or re.match(r"^'([^']*)'$", p)
        if sm:
            sql_parts.append(sm.group(1))
        elif re.match(r'^\$[A-Za-z_][\w>-]*$', p):
            if _is_sql_fragment_var(p):
                return assign + expr + ";"   # leave as-is: not safe to auto-bind
            sql_parts.append("%s")
            params.append(p)
        else:
            return assign + expr + ";"
    if not params:
        return assign + expr + ";"
    joined = "".join(sql_parts).replace("'%s'", "%s").replace('"%s"', "%s")
    bind = ", ".join(params)
    return f'{assign}{handle}->prepare("{joined}", {bind}); /* parameterized by LogicBreaker */'


def _php_call_parameterize(expr, handle='$pdo'):
    """Turn the argument of a $wpdb->get_var("..." . $var) call into a
    prepare() form. Returns None if unsafe (SQL-fragment variable) so the
    caller leaves the code unchanged rather than breaking it."""
    pieces = _split_top_level_dot(expr)
    sql_parts, params = [], []
    for p in pieces:
        p = p.strip()
        sm = re.match(r'^"([^"]*)"$', p) or re.match(r"^'([^']*)'$", p)
        if sm:
            sql_parts.append(sm.group(1))
        elif re.match(r'^\$[A-Za-z_][\w>-]*$', p):
            if _is_sql_fragment_var(p):
                return None
            sql_parts.append("%s")
            params.append(p)
        else:
            return None
    if not params:
        return None
    joined = "".join(sql_parts).replace("'%s'", "%s").replace('"%s"', "%s")
    bind = ", ".join(params)
    return f'{handle}->prepare("{joined}", {bind})'


def _insert_import_in_body(func_src, import_stmt):
    """Insert an import as the first statement INSIDE a function body (correctly
    indented), so splicing the function back into the file never places an import
    between a decorator and its def (which is a syntax error)."""
    lines = func_src.split("\n")
    for i, line in enumerate(lines):
        if re.match(r"\s*def\s+\w+\s*\(.*\)\s*:", line):
            # find the body indent from the next non-empty line
            indent = "    "
            for j in range(i + 1, len(lines)):
                if lines[j].strip():
                    indent = re.match(r"(\s*)", lines[j]).group(1) or "    "
                    break
            lines.insert(i + 1, f"{indent}{import_stmt}")
            return "\n".join(lines)
    # no def found (module-level snippet) -> prepend
    return import_stmt + "\n" + func_src


def _split_top_level_dot(expr):
    """Split a PHP concatenation expression on '.' at the top level (not inside
    quotes and not a decimal point inside a number)."""
    parts = []
    buf = ""
    in_s = None
    i = 0
    while i < len(expr):
        c = expr[i]
        if in_s:
            buf += c
            if c == in_s and expr[i-1] != "\\":
                in_s = None
        elif c in ("'", '"'):
            in_s = c
            buf += c
        elif c == ".":
            parts.append(buf)
            buf = ""
        else:
            buf += c
        i += 1
    if buf.strip():
        parts.append(buf)
    return parts


def _split_top_level_plus(expr):
    """Split a concatenation expression on '+' at the top level (not inside
    quotes). e.g.  '"a" + x + "b"'  ->  ['"a"', 'x', '"b"'] """
    parts = []
    buf = ""
    in_s = None
    i = 0
    while i < len(expr):
        c = expr[i]
        if in_s:
            buf += c
            if c == in_s and expr[i-1] != "\\":
                in_s = None
        elif c in ("'", '"'):
            in_s = c
            buf += c
        elif c == "+":
            parts.append(buf)
            buf = ""
        else:
            buf += c
        i += 1
    if buf.strip():
        parts.append(buf)
    return parts


def _insert_at_body_top(src, block, present_marker=None):
    """Insert `block` (a multi-line string with NO leading indent) at the top of
    the FIRST function body found in `src`, re-indented to the body level. Used by
    the textual fixers to add a self-contained import / helper when only a single
    function slice is available (the LibCST path injects at module scope instead).

    `present_marker`: if this substring already appears in `src`, do nothing
    (idempotence). Returns `src` unchanged if no `def` line is found."""
    if present_marker and present_marker in src:
        return src
    lines = src.split("\n")
    for i, line in enumerate(lines):
        mdef = re.match(r"(\s*)def\s+\w+\s*\(.*\)\s*:\s*$", line)
        if mdef:
            body = mdef.group(1) + "    "
            blk = [(body + bl) if bl.strip() else bl for bl in block.split("\n")]
            return "\n".join(lines[: i + 1] + blk + lines[i + 1 :])
    return src


# ----------------------------------------------------------------------
# SQL Injection -> parameterize / use safe interpolation
# ----------------------------------------------------------------------
def fix_sql_injection(src, language):
    """
    Convert a concatenated/interpolated SQL string into a parameterized query.
    This is a best-effort transform that covers the common shapes; when it
    can't safely transform, it wraps the variable in a clear sanitisation call
    so the detector's "raw concatenation" signal no longer fires.
    """
    if language == "python":
        # Root-cause fix: turn a string-built SQL query into a PARAMETERISED call
        # using positional placeholders (?) + a params tuple -- the portable,
        # sqlite3-correct form. We never emit %s (driver-specific) and never use
        # the execute(*tuple) unpacking hack; the result is the clean, idiomatic
        #     query = "... ? ... ?"        and        cur.execute(query, (a, b))
        new = src

        def _ph_from_fstring(inner):
            """(sql_with_?, [param_src, ...]) from an f-string body, or None."""
            vars_found = re.findall(r"\{([^}{:]+)\}", inner)
            if not vars_found:
                return None
            sql = re.sub(r"\{[^}{:]+\}", "?", inner)
            sql = sql.replace("'?'", "?").replace('"?"', "?")   # unquote placeholders
            return sql, [v.strip() for v in vars_found]

        def _ph_from_concat(expr):
            """(sql_with_?, [param_src, ...]) from a '+'-concatenation, or None."""
            pieces = _split_top_level_plus(expr)
            sql_parts, params = [], []
            for p in pieces:
                p = p.strip()
                sm = re.match(r'^"([^"]*)"$', p) or re.match(r"^'([^']*)'$", p)
                if sm:
                    sql_parts.append(sm.group(1))
                elif re.match(r'^[A-Za-z_][\w\.\[\]"\']*$', p):
                    sql_parts.append("?")
                    params.append(p)
                else:
                    return None
            if not params:
                return None
            sql = "".join(sql_parts).replace("'?'", "?").replace('"?"', "?")
            return sql, params

        def _params_tuple(params):
            tail = "," if len(params) == 1 else ""
            return f"({', '.join(params)}{tail})"

        # 1) INLINE f-string:  .execute(f"...{x}...")  ->  .execute("...?...", (x,))
        def repl_inline_fstring(m):
            built = _ph_from_fstring(m.group(2))
            if not built:
                return m.group(0)
            sql, params = built
            return f'{m.group(1)}("{sql}", {_params_tuple(params)})'
        new = re.sub(r'(\.execute|\.executemany)\s*\(\s*f"([^"]*)"\s*\)',
                     repl_inline_fstring, new, flags=re.S)

        # 2) INLINE concat:  .execute("a" + x + "b")  ->  .execute("a?b", (x,))
        def repl_inline_concat(m):
            built = _ph_from_concat(m.group(2))
            if not built:
                return m.group(0)
            sql, params = built
            return f'{m.group(1)}("{sql}", {_params_tuple(params)})'
        new = re.sub(r'(\.execute|\.executemany)\s*\(\s*((?:"[^"]*"|\'[^\']*\'|[A-Za-z_][\w\.\[\]]*)'
                     r'(?:\s*\+\s*(?:"[^"]*"|\'[^\']*\'|[A-Za-z_][\w\.\[\]]*))+)\s*\)',
                     repl_inline_concat, new)

        # 3) ASSIGNMENT forms:  q = f"...{x}..."   (or   q = "a" + x + "b")   with a
        #    later  cur.execute(q).  Rewrite the assignment to a plain ?-SQL string
        #    and bind the params on the matching execute(q) -> execute(q, (x,)).
        var_params = {}          # varname -> "(a, b)"

        def repl_assign_fstring(m):
            built = _ph_from_fstring(m.group(2))
            if not built:
                return m.group(0)
            sql, params = built
            var_params[m.group(1)] = _params_tuple(params)
            return f'{m.group(1)} = "{sql}"'
        new = re.sub(r'(\b[A-Za-z_]\w*)\s*=\s*f"([^"]*\{[^}]+\}[^"]*)"',
                     repl_assign_fstring, new)

        def repl_assign_concat(m):
            built = _ph_from_concat(m.group(2))
            if not built:
                return m.group(0)
            sql, params = built
            var_params[m.group(1)] = _params_tuple(params)
            return f'{m.group(1)} = "{sql}"'
        new = re.sub(r'(\b[A-Za-z_]\w*)\s*=\s*((?:"[^"]*"|\'[^\']*\'|[A-Za-z_][\w\.\[\]]*)'
                     r'(?:\s*\+\s*(?:"[^"]*"|\'[^\']*\'|[A-Za-z_][\w\.\[\]]*))+)\s*$',
                     repl_assign_concat, new, flags=re.M)

        # bind params on each converted variable's execute() call (clean 2-arg form)
        for _v, _ptuple in var_params.items():
            new = re.sub(rf'(\.execute|\.executemany)\s*\(\s*{re.escape(_v)}\s*\)',
                         rf'\1({_v}, {_ptuple})', new)

        if new != src:
            return new, ("Converted the concatenated/f-string SQL into a parameterized query with "
                         "positional bind placeholders (?) and a params tuple, so user input can no "
                         "longer alter the query structure.")
        return _fallback_sql(src, language)

    if language == "php":
        new = src
        _handle = _php_prepare_handle(src)
        # (a) assignment form: $sql = "<a>" . $var . "<b>" ... ;
        def repl_php_assign(m):
            assign = m.group(1)
            expr = m.group(2)
            return _php_parameterize(assign, expr, _handle)
        new = re.sub(r'(\$\w+\s*=\s*)((?:"[^"]*"|\'[^\']*\'|\$\w+)'
                     r'(?:\s*\.\s*(?:"[^"]*"|\'[^\']*\'|\$\w+))+)\s*;',
                     repl_php_assign, new)

        # (b) direct call form: $wpdb->get_var("..." . $var)  /  $conn->query(...)
        def repl_php_call(m):
            call = m.group(1)
            expr = m.group(2)
            param = _php_call_parameterize(expr, _handle)
            if param is None:
                return m.group(0)
            return f"{call}({param})"
        new = re.sub(r'(\$\w+->(?:get_var|get_results|get_row|get_col|query|prepare))\s*\(\s*'
                     r'((?:"[^"]*"|\'[^\']*\'|\$[\w>-]+)'
                     r'(?:\s*\.\s*(?:"[^"]*"|\'[^\']*\'|\$[\w>-]+))+)\s*\)',
                     repl_php_call, new)

        if new != src:
            return new, ("Replaced string concatenation with a prepared statement / "
                         "$wpdb->prepare() using placeholders, so user input is bound rather "
                         "than concatenated into the SQL text.")
        return _fallback_sql(src, language)

    if language in ("javascript", "typescript"):
        # `... ${x} ...`  ->  parameterized query with ? and a params array
        def repl_tmpl(m):
            inner = m.group(1)
            vars_found = re.findall(r"\$\{([^}]+)\}", inner)
            placeholder = re.sub(r"\$\{[^}]+\}", "?", inner)
            params = ", ".join(v.strip() for v in vars_found)
            return f'"{placeholder}", [{params}]'
        new = re.sub(r"`([^`]*\$\{[^}]+\}[^`]*)`", repl_tmpl, src)
        if new != src:
            return new, ("Replaced the template-literal SQL with a parameterized query (? "
                         "placeholders + params array) so input cannot alter the query.")
        return _fallback_sql(src, language)

    return _fallback_sql(src, language)


def _fallback_sql(src, language):
    """When we can't fully rewrite, neutralise by routing the input through an
    explicit integer/identifier cast or escape that the detector recognises as
    safe. Keeps code shape; closes the raw-concat signal."""
    return None, ("Could not auto-rewrite this query safely; apply a parameterized query / "
                  "prepared statement manually.")


# ----------------------------------------------------------------------
# IDOR -> add an ownership check
# ----------------------------------------------------------------------
def fix_idor(src, language):
    """Insert an ownership/authorization check right after the object is loaded."""
    if language == "python":
        lines = src.split("\n")
        # locate the function signature to read its path parameter (e.g. user_id)
        sig = next((l for l in lines if re.match(r"\s*def\s+\w+\s*\(", l)), "")
        params = re.findall(r"\(([^)]*)\)", sig)
        id_param = None
        if params:
            for p in [x.strip() for x in params[0].split(",")]:
                if p and (p == "id" or p.endswith("_id") or p.endswith("Id")):
                    id_param = p
                    break

        out = []
        injected = False
        # strategy A: object assigned from a loader call -> check that object
        for line in lines:
            out.append(line)
            if not injected and re.search(r"=\s*\w+\.(get|query|filter|find|first|fetchone)\w*\(", line):
                indent = re.match(r"(\s*)", line).group(1)
                var = re.match(r"\s*(\w+)\s*=", line)
                vname = var.group(1) if var else "obj"
                out.append(f"{indent}# ownership check (added by LogicBreaker)")
                out.append(f'{indent}if {vname} is None or getattr({vname}, "owner_id", None) != session.get("user_id"):')
                out.append(f'{indent}    return ("forbidden", 403)')
                injected = True
        if injected:
            return "\n".join(out), ("Added an ownership check after the object lookup: the request "
                                    "is rejected with 403 unless the loaded object belongs to the "
                                    "authenticated user (session user_id).")

        # strategy B: route-param handler with no clear object var -> insert an
        # authorization guard at the top of the body that ties the requested id
        # to the authenticated principal.
        if id_param:
            out = []
            inserted = False
            for line in lines:
                out.append(line)
                if not inserted and re.match(r"\s*def\s+\w+\s*\(", line):
                    indent = re.match(r"(\s*)", lines[lines.index(line) + 1]).group(1) \
                        if lines.index(line) + 1 < len(lines) else "    "
                    out.append(f"{indent}# authorization check (added by LogicBreaker)")
                    out.append(f'{indent}if str({id_param}) != str(session.get("user_id")):')
                    out.append(f'{indent}    return ("forbidden", 403)')
                    inserted = True
            if inserted:
                return "\n".join(out), (f"Added an authorization check at the start of the handler: "
                                        f"the requested `{id_param}` must match the authenticated "
                                        f"user (session user_id), otherwise the request is rejected "
                                        f"with 403. This stops one user from reading another's "
                                        f"records by changing the id in the URL.")
    return None, ("Add an ownership check after loading the object: verify it belongs to the "
                  "authenticated principal before returning it.")


# ----------------------------------------------------------------------
# Broken Authorization (client-trusted role) -> derive role server-side
# ----------------------------------------------------------------------
def fix_broken_auth(src, language):
    if language == "java":
        # replace request.getParameter("role")/body role with a server lookup
        new = re.sub(
            r'(String\s+\w+\s*=\s*)request\.getParameter\(\s*"(role|isAdmin|admin|privilege)"\s*\)\s*;',
            r'\1userService.getRoleFromSession(session); // server-side role (was client-supplied)',
            src)
        if new != src:
            return new, ("Replaced the client-supplied role with a server-side lookup "
                         "(userService.getRoleFromSession), so the caller can no longer set their "
                         "own privilege level.")
    if language == "python":
        new = re.sub(
            r'(\w+\s*=\s*)request\.(form|args|json)\s*(?:\.get\()?\[?\s*["\'](role|is_admin|admin)["\']\s*\]?\)?',
            r'\1get_role_from_session(session)  # server-side role (was client-supplied)',
            src)
        if new != src:
            return new, ("Replaced the client-supplied role with a server-side session lookup so "
                         "the caller cannot escalate their own privileges.")
    return None, ("Resolve the role from the authenticated session / database, never from a "
                  "client-supplied parameter.")


# ----------------------------------------------------------------------
# dispatch
# ----------------------------------------------------------------------
def fix_debug_mode(src, language):
    """Turn debug mode off.

    Handles all common patterns:
      debug=True / debug = True / app.debug=True / DEBUG=True
      app.run(debug=True) / app.run(debug = True)
    Also handles Flask's run configuration in case the debug flag is passed
    as a variable reference.

    IDEMPOTENT: if no `debug=True` is present, returns None (already fixed or
    not applicable)."""
    new = src
    # idempotency: if there's no debug=True, nothing to fix
    if not re.search(r"debug\s*=\s*True", new, re.IGNORECASE) and \
       not re.search(r"DEBUG\s*=\s*True", new):
        return None, None
    # debug=True / debug = True (with optional spaces)
    new = re.sub(r"\bdebug\s*=\s*True\b", "debug=False", new)
    # app.debug=True / app.debug = True
    new = re.sub(r"\bapp\.debug\s*=\s*True\b", "app.debug=False", new)
    # DEBUG=True / DEBUG = True
    new = re.sub(r"\bDEBUG\s*=\s*True\b", "DEBUG=False", new)
    # app.run(debug=True) / app.run(debug = True) / app.run(..., debug=True, ...)
    new = re.sub(r"\bapp\.run\(([^)]*)debug\s*=\s*True", r"app.run(\1debug=False", new)
    # any remaining standalone debug=True inside a function call (e.g. create_app(debug=True))
    new = re.sub(r"(\w+\([^)]*)debug\s*=\s*True", r"\1debug=False", new)
    if new != src:
        return new, ("Disabled debug mode (debug=False). Debug mode exposes stack traces and an "
                     "interactive debugger that can lead to remote code execution in production.")
    return None, ("Disable debug mode in production (set debug=False / DEBUG=False).")


def fix_command_injection_chain(full_source, language):
    """Chain-aware command-injection fix for the common pattern where one
    function BUILDS a shell-string from user input and another RUNS it with
    shell=True (interprocedural). The professional fix removes the shell and uses
    an ARGV LIST at the root.

    Transforms, in the WHOLE file:
        def build_command(host):
            cmd = f"ping -c 1 {host}"           ->  cmd = ["ping", "-c", "1", host]
            return cmd
        def run_command(command):
            subprocess.check_output(command, shell=True, ...)
                                               -> subprocess.check_output(command, ...)  (no shell)

    Returns (new_source, note) or (None, None) if the pattern isn't present.
    Only Python for now.
    """
    if language != "python":
        return None, None
    src = full_source
    changed = False
    wrapped = [False]   # set True when a user-controlled argv element is validated

    # 1) find f-string command builders:  VAR = f"...{x}..."  then  return VAR
    #    rewrite the f-string into an argv list (split on spaces, interpolations
    #    become bare expressions). This keeps it runnable and shell-free.
    def fstring_to_list(fstr_body):
        # split the format string into tokens on whitespace, turning {expr} into
        # the bare expr and quoted literals into strings.
        # e.g.  ping -c 1 {host}  -> ["ping", "-c", "1", _lb_safe_cmd_arg(host)]
        tokens = fstr_body.split()
        parts = []
        for tok in tokens:
            m = re.fullmatch(r"\{([^}{:]+)\}", tok)
            if m:
                # user-controlled positional arg -> validate it (reject option
                # injection / shell metacharacters) before it reaches the command
                wrapped[0] = True
                parts.append(f"_lb_safe_cmd_arg({m.group(1).strip()})")
            elif "{" in tok and "}" in tok:
                # mixed token like host={host}; fall back to f-string element
                inner = re.sub(r"\{([^}{:]+)\}", lambda mm: '" + str(' + mm.group(1).strip() + ') + "', tok)
                parts.append('"' + inner + '"')
            else:
                parts.append('"' + tok + '"')
        return "[" + ", ".join(parts) + "]"

    # rewrite assignments `cmd = f"...{...}..."` whose var is returned, into a list
    def repl_builder(m):
        nonlocal changed
        indent, var, body = m.group(1), m.group(2), m.group(3)
        if "{" not in body:
            return m.group(0)
        lst = fstring_to_list(body)
        changed = True
        return f'{indent}{var} = {lst}'
    src = re.sub(r'^([ \t]*)(\w+)\s*=\s*f"([^"]*\{[^}]+\}[^"]*)"\s*$',
                 repl_builder, src, flags=re.M)

    # 2) remove shell=True from subprocess calls (now the arg is a list -> safe)
    src2 = re.sub(r',\s*shell\s*=\s*True', "", src)
    if src2 != src:
        changed = True
        src = src2

    # 3) direct case in ONE function: subprocess.<fn>(f"...{x}...", shell=True)
    def repl_direct(m):
        nonlocal changed
        call, body = m.group(1), m.group(2)
        if "{" not in body:
            return m.group(0)
        lst = fstring_to_list(body)
        changed = True
        return f'{call}({lst}'
    src = re.sub(r'(subprocess\.\w+)\s*\(\s*f"([^"]*)"(?:\s*,\s*shell\s*=\s*True)?',
                 repl_direct, src, flags=re.S)
    # clean any leftover shell=True from the direct rewrite
    src = re.sub(r',\s*shell\s*=\s*True', "", src)

    if not changed:
        return None, None
    if wrapped[0]:
        src = _insert_module_helper(src, "def _lb_safe_cmd_arg", _CMD_ARG_HELPER)
    return src, ("Removed shell execution at the root: the command is now built as an argument "
                 "list (argv) and subprocess runs WITHOUT a shell (shell=True removed). Shell "
                 "metacharacters in user input (';', '|', '$()', '&') are passed as literal "
                 "arguments and can no longer execute extra commands. User-controlled arguments "
                 "are additionally validated (option-injection and out-of-charset values are "
                 "rejected). Framework-native fix, not blacklist filtering.")


def fix_command_injection(src, language):
    """Replace a shell-invoking call that includes user input with a safe form:
    pass an argument list and disable the shell, or quote the input."""
    if language == "python":
        new = src
        # CASE 1: subprocess.<fn>(f"...{var}...", shell=True)  ->  argv list, no shell
        def subprocess_shell_to_list(m):
            call = m.group(1)
            inner = m.group(2)
            if "{" not in inner:
                return m.group(0)
            # build an argv list (shell-free, runnable). e.g.
            #   subprocess.check_output(f"ping -c 1 {host}", shell=True)
            #   -> subprocess.check_output(["ping", "-c", "1", host])
            tokens = inner.split()
            parts = []
            for tok in tokens:
                mm = re.fullmatch(r"\{([^}{:]+)\}", tok)
                if mm:
                    parts.append(mm.group(1).strip())
                elif "{" in tok:
                    inner2 = re.sub(r"\{([^}{:]+)\}", lambda x: '" + str(' + x.group(1).strip() + ') + "', tok)
                    parts.append('"' + inner2 + '"')
                else:
                    parts.append('"' + tok + '"')
            argv = "[" + ", ".join(parts) + "]"
            return f'{call}({argv}'
        new2 = re.sub(
            r'(subprocess\.\w+)\s*\(\s*f"([^"]*)"\s*,\s*shell\s*=\s*True\s*(?:,\s*text\s*=\s*True\s*)?\)',
            lambda m: subprocess_shell_to_list(m) + ")",
            new, flags=re.S)
        if new2 != new:
            return new2, ("Removed the shell (shell=True) and switched to an argument vector (argv "
                          "list). The command still runs, but injected ';', '|', '$()' are treated "
                          "as literal arguments, not extra commands. Framework-native fix.")

        # CASE 2: os.system / popen with f-string or concatenation -> argv via list
        # os.system(f"ping {x}") -> subprocess.run(["ping", x], shell=False)
        def os_fstring_to_run(m):
            inner = m.group(1)
            if "{" not in inner:
                return m.group(0)
            tokens = inner.split()
            parts = []
            for tok in tokens:
                mm = re.fullmatch(r"\{([^}{:]+)\}", tok)
                if mm:
                    parts.append(mm.group(1).strip())
                else:
                    parts.append('"' + tok + '"')
            return "subprocess.run([" + ", ".join(parts) + "], shell=False)"
        new = re.sub(r'os\.system\s*\(\s*f"([^"]*)"\s*\)', os_fstring_to_run, new)
        new = re.sub(r'os\.popen\s*\(\s*f"([^"]*)"\s*\)', os_fstring_to_run, new)
        # os.popen(...).read() returns output, so use check_output(text=True);
        # os.system(...) just runs, so use subprocess.run.
        def os_concat_to_run(m):
            func = m.group(1)   # system or popen
            head = m.group(2)   # the constant prefix, e.g. "ping -c 1 "
            var = m.group(3)    # the user variable
            has_read = bool(m.group(4))
            tokens = [t for t in head.split() if t]
            parts = ['"' + t + '"' for t in tokens] + [var]
            argv = "[" + ", ".join(parts) + "]"
            if func == "popen" or has_read:
                return f"subprocess.check_output({argv}, text=True)"
            return f"subprocess.run({argv}, shell=False)"
        new = re.sub(r'os\.(system|popen)\s*\(\s*"([^"]*)"\s*\+\s*([A-Za-z_][\w]*)\s*\)'
                     r'(\s*\.read\(\))?',
                     os_concat_to_run, new)
        if new != src:
            if "import subprocess" not in new:
                new = _insert_import_in_body(new, "import subprocess")
            return new, ("Replaced shell execution with subprocess.run using an argument list and "
                         "shell=False. User input is now a literal argument, not shell syntax. "
                         "Framework-native fix, not blacklist filtering.")
    if language in ("javascript", "typescript"):
        new = re.sub(r"\bexec\s*\(", "execFile(", src)
        if new != src:
            return new, ("Switched child_process.exec (which runs a shell) toward execFile, which "
                         "takes an argument array and does not invoke a shell. Pass args as an array.")
    return None, ("Pass command arguments as a list and disable the shell (shell=False / execFile); "
                  "never build a shell string from user input.")


def fix_open_redirect(src, language):
    """Validate the redirect target against an allowlist before redirecting."""
    if language == "python":
        m = re.search(r"redirect\s*\(\s*([A-Za-z_][\w\.\[\]\(\)\"']*)\s*\)", src)
        if m:
            target = m.group(1)
            lines = src.split("\n")
            out = []
            done = False
            for line in lines:
                if not done and "redirect(" in line and target in line:
                    indent = re.match(r"(\s*)", line).group(1)
                    out.append(f"{indent}from urllib.parse import urlparse as _urlparse")
                    out.append(f"{indent}_dest = {target}")
                    out.append(f"{indent}if _urlparse(_dest).netloc not in ('', 'yourdomain.com'):")
                    out.append(f'{indent}    _dest = "/"  # block off-site redirect (added by LogicBreaker)')
                    out.append(re.sub(re.escape(target), "_dest", line, count=1))
                    done = True
                else:
                    out.append(line)
            if done:
                return "\n".join(out), ("Validated the redirect destination: only same-site (empty "
                                        "netloc) or an allowlisted host is permitted; anything else "
                                        "falls back to '/'. This blocks open-redirect phishing.")
    return None, ("Validate the redirect target against an allowlist of trusted hosts; reject "
                  "absolute URLs to other domains.")


def fix_cors(src, language):
    """Replace a wildcard / reflected CORS origin with an allowlist."""
    new = src
    # headers["Access-Control-Allow-Origin"] = "*"  (dict assignment)
    new = re.sub(r'(\[\s*["\']Access-Control-Allow-Origin["\']\s*\]\s*=\s*)["\']\*["\']',
                 r'\1"https://yourdomain.com"', new)
    # header string forms "Access-Control-Allow-Origin: *" / ("...", "*")
    new = re.sub(r'(["\']Access-Control-Allow-Origin["\']\s*[:,]\s*)["\']\*["\']',
                 r'\1"https://yourdomain.com"', new)
    # Flask-CORS origins="*"
    new = re.sub(r'(origins\s*=\s*)["\']\*["\']', r'\1["https://yourdomain.com"]', new)
    # reflected origin: ...Allow-Origin"] = request.headers["Origin"]
    new = re.sub(r'(Access-Control-Allow-Origin["\']\s*\]\s*=\s*)request\.\w+(\[?["\']?[Oo]rigin["\']?\]?|\.get\([^)]*\))',
                 r'\1"https://yourdomain.com"', new)
    if new != src:
        return new, ("Replaced the wildcard/reflected CORS origin with an explicit allowlist "
                     "(https://yourdomain.com). Reflecting the request Origin or using '*' lets any "
                     "site read authenticated responses.")
    return None, ("Set Access-Control-Allow-Origin to a specific allowlisted origin; never echo the "
                  "request Origin or use '*' with credentials.")


def fix_negative_quantity(src, language):
    """Add a quantity > 0 (and price >= 0) validation at the top of the handler."""
    if language == "python":
        # find the parameter that looks like a quantity/amount/price
        sig = next((l for l in src.split("\n") if re.match(r"\s*def\s+\w+\s*\(", l)), "")
        var = None
        body = src
        for cand in ("quantity", "qty", "amount", "count", "price", "total"):
            if re.search(rf"\b{cand}\b", body):
                var = cand
                break
        if var:
            lines = src.split("\n")
            out = []
            inserted = False
            for i, line in enumerate(lines):
                out.append(line)
                # insert after the line that first reads the var from request
                if not inserted and re.search(rf"{var}\s*=", line) and ("request" in line or "json" in line or "form" in line or "args" in line):
                    indent = re.match(r"(\s*)", line).group(1)
                    out.append(f"{indent}# input validation (added by LogicBreaker)")
                    out.append(f"{indent}try:")
                    out.append(f"{indent}    if float({var}) <= 0:")
                    out.append(f'{indent}        return ("invalid quantity", 400)')
                    out.append(f"{indent}except (TypeError, ValueError):")
                    out.append(f'{indent}    return ("invalid quantity", 400)')
                    inserted = True
            if inserted:
                return "\n".join(out), (f"Added server-side validation that `{var}` is a positive "
                                        f"number; non-positive or non-numeric values are rejected "
                                        f"with HTTP 400. This stops negative-quantity / zero-price "
                                        f"abuse.")
    return None, ("Validate that quantity/amount is a positive number server-side and reject "
                  "non-positive or non-numeric values.")


def fix_weak_crypto(src, language):
    """Upgrade weak hashes/ciphers to strong ones.

    Per-call approach: each hashlib.md5/sha1 call is individually evaluated.
    If the ARGUMENT contains a password keyword → use bcrypt (if whole file)
    or SHA-256 (if function body, to avoid import issues).
    Otherwise → use SHA-256.
    """
    if language == "python":
        new = src
        changed = False
        needs_bcrypt_import = False

        password_kws = ("password", "passwd", "pw", "secret", "token", "credential")
        # detect if this is a whole file (has imports) or a function body
        is_whole_file = bool(re.search(r"^\s*(import\s|from\s)", src, re.MULTILINE))

        # Pattern 1: hashlib.md5(X.encode()).hexdigest()
        def _repl_md5_enc(m):
            nonlocal changed, needs_bcrypt_import
            arg = m.group(1)
            if any(kw in arg.lower() for kw in password_kws) and is_whole_file:
                changed = True
                needs_bcrypt_import = True
                return f"bcrypt.hashpw({arg}.encode(), bcrypt.gensalt()).decode()"
            changed = True
            return f"hashlib.sha256({arg}.encode()).hexdigest()"
        new = re.sub(
            r"hashlib\.md5\(([^)]+?)\.encode\(\)\)\.hexdigest\(\)",
            _repl_md5_enc, new)
        new = re.sub(
            r"hashlib\.sha1\(([^)]+?)\.encode\(\)\)\.hexdigest\(\)",
            _repl_md5_enc, new)

        # Pattern 2: hashlib.new("md5", X.encode()).hexdigest()
        def _repl_new_enc(m):
            nonlocal changed, needs_bcrypt_import
            arg = m.group(1)
            if any(kw in arg.lower() for kw in password_kws) and is_whole_file:
                changed = True
                needs_bcrypt_import = True
                return f"bcrypt.hashpw({arg}.encode(), bcrypt.gensalt()).decode()"
            changed = True
            return f'hashlib.new("sha256", {arg}.encode()).hexdigest()'
        new = re.sub(
            r'hashlib\.new\(\s*["\']md5["\']\s*,\s*([^)]+?)\.encode\(\)\s*\)\.hexdigest\(\)',
            _repl_new_enc, new)
        new = re.sub(
            r'hashlib\.new\(\s*["\']sha1["\']\s*,\s*([^)]+?)\.encode\(\)\s*\)\.hexdigest\(\)',
            _repl_new_enc, new)

        # Pattern 3: hashlib.md5(X) without .encode().hexdigest()
        def _repl_md5_bare(m):
            nonlocal changed, needs_bcrypt_import
            arg = m.group(1)
            if any(kw in arg.lower() for kw in password_kws) and is_whole_file:
                changed = True
                needs_bcrypt_import = True
                return f"bcrypt.hashpw(str({arg}).encode(), bcrypt.gensalt())"
            changed = True
            return f"hashlib.sha256({arg})"
        new = re.sub(r"hashlib\.md5\(([^)]+)\)", _repl_md5_bare, new)
        new = re.sub(r"hashlib\.sha1\(([^)]+)\)", _repl_md5_bare, new)

        if changed:
            if needs_bcrypt_import and "import bcrypt" not in new:
                lines = new.split("\n")
                last_import = 0
                for i, ln in enumerate(lines):
                    if re.match(r"^\s*(import\s|from\s)", ln):
                        last_import = i
                lines.insert(last_import + 1, "import bcrypt")
                new = "\n".join(lines)
            return new, ("Upgraded weak hash: password hashes upgraded to bcrypt (if whole file) "
                         "or SHA-256 (if function body). Cache-key/checksum uses upgraded to SHA-256. "
                         "NOTE: for production password storage, always use bcrypt/argon2.")
    if language in ("javascript", "typescript"):
        new = re.sub(r"createHash\(\s*['\"]md5['\"]\s*\)", "createHash('sha256')", src)
        new = re.sub(r"createHash\(\s*['\"]sha1['\"]\s*\)", "createHash('sha256')", new)
        if new != src:
            return new, ("Upgraded the weak hash (MD5/SHA-1) to SHA-256. For passwords use bcrypt/"
                         "argon2 rather than a bare hash.")
    if language == "php":
        new = re.sub(r"\bmd5\s*\(", "hash('sha256', ", src)
        new = re.sub(r"\bsha1\s*\(", "hash('sha256', ", new)
        if new != src:
            return new, ("Upgraded MD5/SHA-1 to SHA-256 via hash('sha256', ...). For passwords use "
                         "password_hash() with bcrypt/argon2.")
    return None, ("Use SHA-256+ for integrity and bcrypt/argon2/PBKDF2 for passwords; replace DES/"
                  "RC4 with AES-GCM.")


def fix_missing_auth(src, language):
    """Insert an authentication guard at the top of a sensitive handler."""
    if language == "python":
        lines = src.split("\n")
        out = []
        inserted = False
        for i, line in enumerate(lines):
            out.append(line)
            if not inserted and re.match(r"\s*def\s+\w+\s*\(", line):
                nxt = lines[i + 1] if i + 1 < len(lines) else "    pass"
                indent = re.match(r"(\s*)", nxt).group(1) or "    "
                out.append(f"{indent}# authentication check (added by LogicBreaker)")
                out.append(f'{indent}if not session.get("user_id"):')
                out.append(f'{indent}    return ("authentication required", 401)')
                inserted = True
        if inserted:
            return "\n".join(out), ("Added an authentication guard: the handler now rejects "
                                    "unauthenticated callers (no session user) with HTTP 401 before "
                                    "performing the sensitive action.")
    return None, ("Require authentication before this sensitive action (check the session / a valid "
                  "token) and reject anonymous requests.")


def fix_ssrf(src, language):
    """Restrict an outbound request to an allowlist and block internal targets."""
    if language == "python":
        m = re.search(r"(requests\.(get|post|put|delete)|urllib\.request\.urlopen|httpx\.\w+)\s*\(\s*([A-Za-z_][\w\.\[\]]*)", src)
        if m:
            url_var = m.group(3)
            lines = src.split("\n")
            out, done = [], False
            for line in lines:
                if not done and re.search(r"(requests\.|urlopen|httpx\.)", line) and url_var in line:
                    indent = re.match(r"(\s*)", line).group(1)
                    out.append(f"{indent}from urllib.parse import urlparse as _up")
                    out.append(f"{indent}_host = _up({url_var}).hostname or ''")
                    out.append(f"{indent}if _host not in ('api.yourdomain.com',) or _host in ('localhost','127.0.0.1','0.0.0.0','169.254.169.254'):")
                    out.append(f'{indent}    return ("blocked outbound request", 403)  # SSRF guard (LogicBreaker)')
                    done = True
                out.append(line)
            if done:
                return "\n".join(out), ("Constrained the outbound request to an allowlisted host and "
                                        "blocked internal/metadata addresses (localhost, 127.0.0.1, "
                                        "169.254.169.254). This stops SSRF to internal services.")
    return None, ("Validate the outbound URL against an allowlist of hosts and block private / "
                  "link-local / metadata addresses before making the request.")


def fix_xxe(src, language):
    """Disable external entities in XML parsing."""
    if language == "python":
        if "etree" in src or "lxml" in src:
            new = src
            # add a no-network, no-entity parser to lxml calls
            new = re.sub(r"etree\.parse\(\s*([^)]+)\)",
                         r"etree.parse(\1, etree.XMLParser(resolve_entities=False, no_network=True))",
                         new)
            new = re.sub(r"etree\.fromstring\(\s*([^)]+)\)",
                         r"etree.fromstring(\1, etree.XMLParser(resolve_entities=False, no_network=True))",
                         new)
            if new != src:
                return new, ("Disabled external-entity resolution and network access in the XML "
                             "parser (resolve_entities=False, no_network=True), preventing XXE file "
                             "reads and SSRF. For full safety use the defusedxml library.")
    return None, ("Disable DOCTYPE / external-entity processing in the XML parser (e.g. use "
                  "defusedxml, or set resolve_entities=False and no_network=True).")


def fix_insecure_deserialization(src, language):
    """Replace unsafe deserialization with a SAFE loader that actually removes the
    RCE. yaml.load -> yaml.safe_load (in-place). For pickle/dill we route the call
    through a restricted unpickler that refuses any non-builtin global (blocking
    os.system / subprocess / __reduce__ gadgets) while preserving the pickle wire
    format -- injected as a self-contained local so it works on a function slice."""
    if language == "python":
        new = src
        # yaml.load(...) -> yaml.safe_load(...)  (safe, in-place, valid)
        if "yaml.load(" in new and "safe_load" not in new:
            y = re.sub(r"yaml\.load\(([^)]*?)\)", r"yaml.safe_load(\1)", new)
            if y != src:
                return y, ("Replaced yaml.load with yaml.safe_load, which refuses the Python-object "
                           "tags that allow arbitrary code execution on crafted YAML.")
        # pickle / dill on untrusted input -> restricted unpickler (real mitigation).
        if re.search(r"\b(?:pickle|cPickle|dill)\.loads\s*\(", new) or \
           re.search(r"\b(?:pickle|cPickle|dill)\.load\s*\(", new):
            p = re.sub(r"\b(?:pickle|cPickle|dill)\.loads\s*\(([^()]*)\)",
                       r"_lb_safe_loads(\1)", new)
            p = re.sub(r"\b(?:pickle|cPickle|dill)\.load\s*\(([^()]*)\)",
                       r"_lb_safe_load(\1)", p)
            if p != new:
                p = _insert_at_body_top(p, _PICKLE_LOCAL_GUARD, present_marker="def _lb_safe_loads")
                return p, ("Routed pickle deserialization through a restricted unpickler that refuses "
                           "any non-builtin global (e.g. posix.system), so a crafted payload can no "
                           "longer execute code. The pickle wire format is preserved; for new code "
                           "prefer JSON, or sign the payload (HMAC) and verify before deserializing.")
            # rewrite did not apply (unusual shape) -> precise recommendation
            return None, ("pickle/dill deserialization of user-controlled data allows remote code "
                          "execution. Route it through a restricted unpickler that whitelists only "
                          "safe built-in types, or switch the format to signed JSON.")
    return None, ("Never deserialize untrusted data with pickle / yaml.load / native serializers; "
                  "use a safe format like JSON or yaml.safe_load.")


def fix_code_injection(src, language):
    """Neutralise eval()/exec() of attacker-influenced input (CWE-94).
    eval(x) -> _lb_safe_eval(x) (literals only, never runs code);
    exec(x) -> _lb_no_exec(x) (refuses; exec has no safe form).
    Works regardless of the argument shape (variable, f-string, call)."""
    if language != "python":
        return None, ("Never eval()/exec() dynamic input. Use ast.literal_eval for data, or an "
                      "explicit allow-list dispatch for code paths.")
    new = src
    # eval(...) -> _lb_safe_eval(...)   (not preceded by a . or word char, so we
    # don't touch obj.eval / ast.literal_eval / names ending in 'eval')
    new = re.sub(r"(?<![.\w])eval\s*\(", "_lb_safe_eval(", new)
    new = re.sub(r"(?<![.\w])exec\s*\(", "_lb_no_exec(", new)
    if new == src:
        return None, ("Never eval()/exec() dynamic input.")
    new = _insert_module_helper(new, "def _lb_safe_eval", _SAFE_EVAL_HELPER)
    return new, ("Replaced eval() with _lb_safe_eval (ast.literal_eval -- parses only literal data and "
                 "can never execute code) and exec() with a guard that refuses dynamic input. This "
                 "closes the arbitrary-code-execution sink at the root.")


def fix_insecure_randomness(src, language):
    """Replace the predictable `random` module with a CSPRNG (CWE-330).
    `random.<fn>(...)` -> `_lb_secure_rng.<fn>(...)` where _lb_secure_rng is a
    secrets.SystemRandom() (identical API, cryptographically strong)."""
    if language != "python":
        return None, ("Use a cryptographically secure RNG (e.g. the `secrets` module) for any "
                      "security-sensitive value.")
    # rewrite module-qualified calls: random.random/ randint/ choice/ getrandbits/...
    new = re.sub(r"(?<![.\w])random\.(random|randint|randrange|choice|choices|"
                 r"getrandbits|shuffle|sample|uniform|betavariate|gauss|normalvariate)\b",
                 r"_lb_secure_rng.\1", src)
    if new == src:
        return None, ("Use the `secrets` module / secrets.SystemRandom() instead of `random` for "
                      "security values.")
    new = _insert_module_helper(new, "_lb_secure_rng = _lb_secrets", _SECURE_RNG_HELPER)
    return new, ("Swapped the predictable `random` module for a CSPRNG (secrets.SystemRandom, same "
                 "API) so the generated values can no longer be predicted by an attacker who knows "
                 "the time/PID seed.")


def _path_confine_block(indent, pathexpr, base_literal, ret_stmt):
    """Build a basename + realpath containment guard, returning the safe path in
    a fresh `_lb_safe_path` variable. Works for any path EXPRESSION."""
    return [
        f"{indent}import os as _lb_os",
        f"{indent}_lb_base = _lb_os.path.realpath({base_literal})",
        f"{indent}_lb_safe_path = _lb_os.path.realpath("
        f"_lb_os.path.join(_lb_base, _lb_os.path.basename(str({pathexpr}))))",
        f"{indent}if _lb_safe_path != _lb_base and not _lb_safe_path.startswith(_lb_base + _lb_os.sep):",
        f"{indent}    {ret_stmt}",
    ]


def _base_dir_from_path_arg(arg):
    """Extract a fixed base directory from a built path argument.
    f"/tmp/{x}" -> "/tmp" ; "/var/www/" + x -> "/var/www" ; default "." ."""
    # f-string prefix up to the first {
    m = re.search(r"""f(['"])(.*?)\{""", arg)
    if m:
        prefix = m.group(2)
        d = prefix.rstrip("/")
        return '"' + (d or ".") + '"'
    # leading "literal" + var
    m = re.search(r"""(['"])([^'"]*)\1\s*\+""", arg)
    if m:
        d = m.group(2).rstrip("/")
        return '"' + (d or ".") + '"'
    return '"."'


def _joined_var_in_path(arg):
    """Return the variable interpolated/concatenated into a path arg, or None."""
    m = re.search(r"\{\s*([A-Za-z_][\w.]*)\s*\}", arg)          # f"...{var}..."
    if m:
        return m.group(1)
    m = re.search(r"""['"]\s*[.+]\s*([A-Za-z_][\w.]*)""", arg)   # "..." + var
    if m:
        return m.group(1)
    m = re.search(r"""([A-Za-z_][\w.]*)\s*[.+]\s*['"]""", arg)   # var + "..."
    if m:
        return m.group(1)
    return None


def fix_path_traversal(src, language):
    """Confine a user-controlled file path to a base directory and reject
    traversal. Robust across argument shapes:
      open(var)                         -> guard on var
      open(f"/tmp/{name}")              -> guard on the built path
      open("/dir/" + name)              -> guard on the built path
      file.save(f"/uploads/{fname}")    -> secure_filename + guard (upload)
    The dangerous call is rewritten to use the validated `_lb_safe_path`.

    IDEMPOTENT: if the source already contains `_lb_safe_path` or `_lb_base`,
    the fix was already applied -- return None to avoid duplicating the guard
    block on re-runs."""
    if language != "python":
        return None, ("Confine the path to a safe base directory and reject path traversal sequences.")
    # idempotency: don't apply the fix twice (check BOTH regex and CST variable names)
    if "_lb_safe_path" in src or "_lb_base" in src or \
       "_safe_path" in src or "_BASE" in src:
        return None, None
    lines = src.split("\n")

    # ---- (a) file upload:  X.save(<path>)  --------------------------------
    for i, line in enumerate(lines):
        sm = re.search(r"(\s*)([A-Za-z_]\w*)\.save\s*\(\s*(.+?)\s*\)\s*$", line)
        if not sm:
            continue
        indent, arg = sm.group(1), sm.group(3)
        base = _base_dir_from_path_arg(arg) if re.search(r"[/\\]", arg) else '"./uploads"'
        # use the user-controlled component directly (e.g. file.filename) rather
        # than the original built path, so no traversal-looking f-string remains.
        joined = _joined_var_in_path(arg)
        name_src = joined if joined else f"_lb_os.path.basename(str({arg}))"
        in_fn = _in_function(lines, i)
        deny = 'return ("forbidden", 403)' if in_fn else 'raise PermissionError("path traversal blocked")'
        block = [
            f"{indent}from werkzeug.utils import secure_filename as _lb_secure_name",
            f"{indent}import os as _lb_os",
            f"{indent}_lb_base = _lb_os.path.realpath({base})",
            f"{indent}_lb_name = _lb_secure_name(_lb_os.path.basename(str({name_src})))",
            f"{indent}_lb_safe_path = _lb_os.path.realpath(_lb_os.path.join(_lb_base, _lb_name))",
            f"{indent}if not _lb_safe_path.startswith(_lb_base + _lb_os.sep):",
            f"{indent}    {deny}",
        ]
        new_line = f"{indent}{sm.group(2)}.save(_lb_safe_path)"
        out = lines[:i] + block + [new_line] + lines[i+1:]
        return "\n".join(out), ("Hardened the file upload: the user-supplied filename is reduced with "
                                "werkzeug.secure_filename and the resolved path must stay under the "
                                "upload base directory, so `../` names can no longer write outside it.")

    # ---- (b) open()/readfile-style sinks  ---------------------------------
    sink = r"(open|io\.open|os\.open)"
    for i, line in enumerate(lines):
        om = re.search(sink + r"\s*\(\s*(.+?)(,|\))", line)
        if not om:
            continue
        arg = om.group(2).strip()
        indent = re.match(r"(\s*)", line).group(1)
        ret = 'return ("forbidden", 403)' if _in_function(lines, i) \
              else 'raise PermissionError("path traversal blocked")'
        # bare variable argument
        if re.fullmatch(r"[A-Za-z_]\w*", arg):
            base = '"./safe_files"'
            block = _path_confine_block(indent, arg, base, ret)
            new_line = re.sub(re.escape(arg), "_lb_safe_path", line, count=1)
            out = lines[:i] + block + [new_line] + lines[i+1:]
            return "\n".join(out), ("Confined the user-supplied path: reduced to a basename and the "
                                    "resolved real path must stay under the base directory, otherwise "
                                    "the request is rejected. Blocks ../ traversal and absolute paths.")
        # built path: f"/dir/{var}"  or  "/dir/" + var
        if re.search(r"[/\\]", arg) and _joined_var_in_path(arg):
            base = _base_dir_from_path_arg(arg)
            block = _path_confine_block(indent, arg, base, ret)
            # replace the whole built-path argument with the validated path
            new_line = line[:om.start(2)] + "_lb_safe_path" + line[om.end(2):]
            out = lines[:i] + block + [new_line] + lines[i+1:]
            return "\n".join(out), ("Confined the constructed path to its intended base directory: the "
                                    "user-controlled component is reduced to a basename and the resolved "
                                    "real path must stay under the base, otherwise the request is "
                                    "rejected. Blocks ../ traversal and absolute-path escapes.")
    return None, ("Confine the path to a safe base directory and reject path traversal sequences.")


def _in_function(lines, idx):
    """True if line `idx` is inside a def (so `return` is legal)."""
    indent = len(lines[idx]) - len(lines[idx].lstrip())
    for j in range(idx, -1, -1):
        s = lines[j].strip()
        if not s:
            continue
        ind = len(lines[j]) - len(lines[j].lstrip())
        if ind < indent and s.startswith("def "):
            return True
        if ind < indent and (s.startswith("class ") or not s.startswith(("def ", "@", "#"))):
            if ind == 0:
                return False
    return False


def fix_ssti(src, language):
    """Close server-side template injection (CWE-1336). Root cause: user input is
    fed into render_template_string. The strong fix removes the dynamic template
    entirely -- the user value is HTML-escaped and returned directly, so no Jinja
    evaluation of attacker input is possible. Handles BOTH the inline form
    render_template_string(f"...{x}...") AND the variable form
    tmpl = f"...{x}..." ; render_template_string(tmpl)."""
    if language != "python":
        return None, ("Never build a template from user input; render a fixed template and pass user "
                      "values as autoescaped context variables.")
    new, changed = _rewrite_render_template_string(src)
    if changed:
        return new, ("Removed render_template_string on user input: the interpolated values are now "
                     "HTML-escaped and returned directly, so the template engine never evaluates "
                     "attacker input. This closes server-side template injection (e.g. {{7*7}} is no "
                     "longer executed).")
    return None, ("Never build a template from user input. Pass user values as context variables to a "
                  "fixed template, and use a sandboxed environment.")


def fix_reflected_xss(src, language):
    """Close reflected XSS (CWE-79). Two paths:
      (1) render_template_string(f"...{x}...")  -> escape + return directly
          (shared with the SSTI fix; also neutralises XSS because the value is
          HTML-escaped);
      (2) return "<...>" + var + ...           -> wrap each bare var in escape()."""
    if language != "python":
        return None, ("HTML-escape user input before placing it in the response (template "
                      "autoescaping, or an escaping function for your language).")
    # path (1): render_template_string with an interpolated value
    new, changed = _rewrite_render_template_string(src)
    if changed:
        return new, ("HTML-escaped the reflected user input and returned it directly instead of "
                     "through render_template_string, so <script> becomes &lt;script&gt; -- closing "
                     "the reflected XSS.")
    # path (2): direct string concatenation into an HTML response
    flag = {"v": False}

    def repl_concat_html(m):
        prefix, expr = m.group(1), m.group(2)
        pieces = _split_top_level_plus(expr)
        if not any(re.match(r'^\s*[\"\']', p) and "<" in p for p in pieces):
            return m.group(0)
        out = []
        for p in pieces:
            ps = p.strip()
            if re.match(r"^[A-Za-z_]\w*$", ps):
                out.append(f"str(_lb_escape({ps}))"); flag["v"] = True
            else:
                out.append(ps)
        return prefix + " + ".join(out)

    new2 = re.sub(r'(return\s+)((?:"[^"]*"|\'[^\']*\'|[A-Za-z_]\w*)'
                  r'(?:\s*\+\s*(?:"[^"]*"|\'[^\']*\'|[A-Za-z_]\w*))+)',
                  repl_concat_html, src)
    if flag["v"]:
        new2 = _inject_escape_import(new2)
        return new2, ("Wrapped the reflected user input in markupsafe.escape() so HTML metacharacters "
                      "are neutralised, closing the reflected XSS.")
    return None, ("HTML-escape user input before writing it into the response (markupsafe.escape, or "
                  "render through a template with autoescaping enabled).")


def _rewrite_render_template_string(src):
    """Shared SSTI/XSS transform. Turn a render_template_string call whose template
    is built from user input into a direct, HTML-escaped return. Returns
    (new_src, changed). Handles the inline f-string form and the
    'tmpl = f"..."; render_template_string(tmpl)' variable form.

    ALSO handles the static-template-with-context-variable form:
        render_template_string('<h1>Hello {{ name }}</h1>', name=name)
    by adding the `|e` (escape) filter to each context variable reference in
    the template string, so Jinja2 auto-escapes them.
    """
    changed = [False]

    def _escape_fstring(fbody):
        # wrap each {expr} in str(_lb_escape(expr)); keep literal text as-is
        return re.sub(r"\{([^}{:]+)\}",
                      lambda mm: "{" + f"_lb_escape({mm.group(1).strip()})" + "}", fbody)

    # inline:  render_template_string(f"...")  -> f"..."(escaped)
    def repl_inline(m):
        q, body = m.group(1), m.group(2)
        changed[0] = True
        return 'f' + q + _escape_fstring(body) + q

    new = re.sub(r"""render_template_string\(\s*f(['"])(.*?)\1\s*\)""", repl_inline, src)

    # variable form: find  TMPL = f"..."  then  render_template_string(TMPL)
    vm = re.search(r"""(\b[A-Za-z_]\w*)\s*=\s*f(['"])(.*?)\2""", new)
    if vm:
        var, q, body = vm.group(1), vm.group(2), vm.group(3)
        if re.search(r"render_template_string\(\s*" + re.escape(var) + r"\s*\)", new):
            # rewrite the assignment to an escaped f-string and return it directly
            new = re.sub(re.escape(vm.group(0)),
                         f"{var} = f{q}{_escape_fstring(body)}{q}", new, count=1)
            new = re.sub(r"render_template_string\(\s*" + re.escape(var) + r"\s*\)",
                         var, new, count=1)
            changed[0] = True

    # static-template-with-context form:
    #   render_template_string('<h1>Hello {{ name }}</h1>', name=name)
    # -> add |e filter to each {{ var }} in the template string
    # This is the safest fix for SSTI/XSS when the template is static but
    # receives user-controlled context variables.
    def _add_escape_filter(m):
        # m.group(1) is the variable name inside {{ }}
        var_expr = m.group(1).strip()
        # don't double-escape if |e is already there
        if "|e" in var_expr or "| escape" in var_expr:
            return m.group(0)
        changed[0] = True
        return "{{ " + var_expr + " | e }}"

    # find render_template_string('<template>', var=var, ...) calls
    def repl_static_template(m):
        template_str = m.group(1)
        # add |e to each {{ var }} in the template
        new_template = re.sub(r"\{\{\s*([^}{}|]+?)\s*\}\}", _add_escape_filter, template_str)
        return "render_template_string(" + new_template + m.group(2)

    # match render_template_string('<template>', ...rest...)
    new = re.sub(
        r"""render_template_string\(\s*(['"])(.*?)\1\s*(,\s*[^)]*\s*)\)""",
        lambda m: repl_static_template_with_quote(m, _add_escape_filter, changed),
        new
    )

    if changed[0]:
        new = _inject_escape_import(new)
    return new, changed[0]


def repl_static_template_with_quote(m, add_escape_fn, changed_ref):
    """Helper for _rewrite_render_template_string: handles
    render_template_string('<template>', ...) by adding |e to each {{ var }}."""
    q = m.group(1)
    template_str = m.group(2)
    rest = m.group(3)  # the ", name=name" part
    # add |e to each {{ var }} in the template
    def _esc(mm):
        var_expr = mm.group(1).strip()
        if "|e" in var_expr or "| escape" in var_expr:
            return mm.group(0)
        changed_ref[0] = True
        return "{{ " + var_expr + " | e }}"
    new_template = re.sub(r"\{\{\s*([^}{}|]+?)\s*\}\}", _esc, template_str)
    return f"render_template_string({q}{new_template}{q}{rest})"


def _inject_escape_import(src):
    """Insert `from markupsafe import escape as _lb_escape` at the TOP OF THE BODY
    of every function that uses _lb_escape, so the name is always in scope. This
    is decorator-safe (the import goes after the `def` line, never between a
    decorator and its def) and works whether `src` is a single function slice or
    a whole file with many functions."""
    if "escape as _lb_escape" in src:
        return src
    lines = src.split("\n")
    use_lines = [i for i, l in enumerate(lines) if "_lb_escape(" in l]
    if not use_lines:
        return src
    def_indices = set()
    for ui in use_lines:
        use_indent = len(lines[ui]) - len(lines[ui].lstrip())
        for j in range(ui, -1, -1):
            s = lines[j].lstrip()
            ind = len(lines[j]) - len(lines[j].lstrip())
            if s.startswith("def ") and ind < use_indent:
                def_indices.add(j)
                break
    if not def_indices:
        # module-level use -> safe to place at file top
        return _insert_module_helper(src, "escape as _lb_escape",
                                     "from markupsafe import escape as _lb_escape")
    for di in sorted(def_indices, reverse=True):   # bottom-up keeps indices valid
        body_indent = " " * ((len(lines[di]) - len(lines[di].lstrip())) + 4)
        lines.insert(di + 1, body_indent + "from markupsafe import escape as _lb_escape")
    return "\n".join(lines)


def fix_jwt(src, language):
    """Enforce signature verification and an algorithm allowlist."""
    if language == "python":
        new = src
        new = re.sub(r"verify\s*=\s*False", "verify=True", new)
        new = re.sub(r"jwt\.decode\(([^)]*?)\)",
                     lambda m: ("jwt.decode(" + m.group(1) + (", algorithms=['HS256']" if "algorithms" not in m.group(1) else "") + ")"),
                     new)
        if new != src:
            return new, ("Enabled JWT signature verification (verify=True) and pinned an algorithm "
                         "allowlist (HS256), preventing alg=none and signature-skip attacks.")
    return None, ("Always verify the JWT signature and restrict algorithms to an explicit allowlist; "
                  "reject 'none'.")


def fix_mass_assignment(src, language):
    """Restrict object updates to an explicit field allowlist."""
    if language == "python":
        # **request.json / **request.form spread into a model -> note + guard
        if re.search(r"\*\*\s*request\.(json|form|get_json\(\))", src):
            new = re.sub(r"\*\*\s*request\.(json|form|get_json\(\))",
                         r"**{k: request.\1[k] for k in ('name','email') if k in request.\1}",
                         src)
            if new != src:
                return new, ("Restricted mass-assignment to an explicit field allowlist "
                             "('name','email'), so attackers can't set privileged fields like "
                             "is_admin by adding them to the request body.")
    return None, ("Bind only an explicit allowlist of fields from the request; never spread the whole "
                  "request body into a model (which lets users set privileged fields).")


def fix_hardcoded_secret(src, language):
    """Move a hardcoded literal secret to an environment variable."""
    if language == "python":
        new = re.sub(r'(\b(?:api[_-]?key|secret|password|token)\s*=\s*)["\'][^"\']{8,}["\']',
                     lambda m: m.group(1) + 'os.environ.get("APP_SECRET")  # set via environment (LogicBreaker)',
                     src, count=1, flags=re.I)
        if new != src:
            if not re.search(r"^\s*import os\b|^\s*import os,|\bimport os\b", new, re.MULTILINE):
                # the secret line is module-level (not indented inside a def), so
                # the import must go at the TOP of the file, not inside a function.
                first_assign = re.search(r"^([ \t]*)(?:api[_-]?key|secret|password|token)\s*=",
                                         new, re.IGNORECASE | re.MULTILINE)
                indented = bool(first_assign and first_assign.group(1))
                if indented:
                    new = _insert_import_in_body(new, "import os")
                else:
                    new = "import os\n" + new
            return new, ("Moved the hardcoded secret out of source into an environment "
                                "variable (os.environ.get). Rotate the exposed value. Secrets in code "
                                "leak through version control.")
    return None, ("Move the secret to an environment variable or secrets manager and rotate the "
                  "exposed value; never commit secrets to source.")


def fix_price_manipulation(src, language):
    """Validate / recompute price server-side; reject client-set prices <= 0."""
    if language == "python":
        for cand in ("price", "amount", "total", "cost"):
            if re.search(rf"\b{cand}\b\s*=.*request", src):
                lines = src.split("\n"); out=[]; done=False
                for line in lines:
                    out.append(line)
                    if not done and re.search(rf"{cand}\s*=", line) and "request" in line:
                        indent = re.match(r"(\s*)", line).group(1)
                        out.append(f"{indent}# server-side price validation (added by LogicBreaker)")
                        out.append(f"{indent}try:")
                        out.append(f"{indent}    if float({cand}) <= 0:")
                        out.append(f'{indent}        return ("invalid price", 400)')
                        out.append(f"{indent}except (TypeError, ValueError):")
                        out.append(f'{indent}    return ("invalid price", 400)')
                        done=True
                if done:
                    return "\n".join(out), (f"Added server-side validation that `{cand}` is positive; "
                                            f"client-supplied non-positive prices are rejected. Best "
                                            f"practice: look the price up server-side, never trust the "
                                            f"client value.")
    return None, ("Never trust a client-supplied price/amount; look it up or recompute it server-side "
                  "and validate it is positive.")


def fix_rate_limit(src, language):
    """Add a clean, thread-safe in-process rate-limit guard to a sensitive
    handler. Self-contained: it lazily creates a shared {ip: [timestamps]} bucket
    plus a Lock in the module globals on first use, so it works correctly even
    when patched into a single function (no separate module-level helper needed)."""
    if language == "python":
        lines = src.split("\n"); out = []; done = False
        for i, line in enumerate(lines):
            out.append(line)
            if not done and re.match(r"\s*def\s+\w+\s*\(", line):
                base = re.match(r"(\s*)", line).group(1)
                nxt = lines[i + 1] if i + 1 < len(lines) else ""
                indent = re.match(r"(\s*)", nxt).group(1) if nxt.strip() else base + "    "
                out.extend([
                    f"{indent}# rate limit (added by LogicBreaker): 10 req/min per client -> HTTP 429.",
                    f"{indent}# Thread-safe in-process bucket; for multiple workers use Redis/Flask-Limiter.",
                    f"{indent}import time as _lb_t, threading as _lb_thr",
                    f'{indent}_lb_rl = globals().setdefault("_LB_RL", {{"hits": {{}}, "lock": _lb_thr.Lock()}})',
                    f'{indent}_lb_ip = getattr(request, "remote_addr", "anon")',
                    f'{indent}with _lb_rl["lock"]:',
                    f"{indent}    _lb_now = _lb_t.time()",
                    f'{indent}    _lb_hits = [t for t in _lb_rl["hits"].get(_lb_ip, []) if _lb_now - t < 60]',
                    f"{indent}    if len(_lb_hits) >= 10:",
                    f'{indent}        return ("Too Many Requests", 429)',
                    f'{indent}    _lb_hits.append(_lb_now); _lb_rl["hits"][_lb_ip] = _lb_hits',
                ])
                done = True
        if done:
            return "\n".join(out), ("Added a thread-safe per-client in-process rate limit (10 requests/"
                                    "minute -> HTTP 429) to blunt brute force/abuse. For multiple workers, "
                                    "back it with Redis or use Flask-Limiter so limits hold across processes.")
    return None, ("Add per-account and per-IP rate limiting / exponential backoff / lockout to this "
                  "sensitive endpoint (e.g. Flask-Limiter, Redis token bucket).")


def fix_weak_auth(src, language):
    """Harden a static-credential check. A full fix (real sessions/JWT) can't be
    safely synthesised without rewriting the app, so we apply the safe, valid
    improvement: constant-time comparison via hmac.compare_digest (defeats timing
    attacks) and leave a clear recommendation for the structural fix."""
    if language == "python":
        import re
        # key == SECRET  ->  hmac.compare_digest(str(key), str(SECRET))
        m = re.search(r"\bif\s+(\w+)\s*==\s*(\w+)\s*:", src)
        if m:
            a, b = m.group(1), m.group(2)
            new = src.replace(f"if {a} == {b}:",
                              f"if hmac.compare_digest(str({a}), str({b})):", 1)
            if new != src:
                new = _insert_import_in_body(new, "import hmac")
                return new, ("Replaced the `==` credential check with a constant-time comparison "
                             "(hmac.compare_digest) to defeat timing attacks. IMPORTANT: this is only "
                             "a partial mitigation. The real fix is to stop authenticating with a "
                             "static key in the query string -- use per-user credentials with a "
                             "server-side session or a signed token (JWT) sent in the Authorization "
                             "header.")
    return None, ("Replace the static-credential check with a real auth mechanism: per-user "
                  "credentials, server-side sessions or signed tokens (JWT), secrets in headers not "
                  "the query string, and constant-time comparison (hmac.compare_digest).")


def fix_sensitive_info_exposure(src, language):
    """Stop returning secrets / environment values directly to the client. The
    handler is rewritten to return HTTP 403 instead of leaking configuration."""
    if language != "python":
        return None, ("Do not return secrets, environment variables or stack traces to clients; "
                      "gate behind auth and return a generic error.")
    deny = 'return ("Not authorized to view this resource", 403)'
    new = re.sub(r'return\s+os\.(?:environ\.get|getenv)\s*\([^\n]*\)', deny, src)
    new = re.sub(r'return\s+os\.environ\s*\[[^\]\n]+\]', deny, new)
    new = re.sub(r'return\s+(?:current_app\.)?config\s*\[[^\]\n]+\]', deny, new)
    if new != src:
        return new, ("Replaced direct exposure of a secret/environment value with an HTTP 403, so the "
                     "endpoint no longer discloses sensitive configuration to callers.")
    return None, ("Do not return secrets/environment values to clients; gate behind authentication "
                  "and return a generic response.")


FIXERS = {
    "SQL Injection": fix_sql_injection,
    "Insecure Direct Object Reference (IDOR)": fix_idor,
    "Broken Authorization (client-trusted role)": fix_broken_auth,
    "Broken Authentication (static credential)": fix_weak_auth,
    "Path Traversal": fix_path_traversal,
    "Debug Mode / Verbose Errors Enabled": fix_debug_mode,
    "OS Command Injection": fix_command_injection,
    "Open Redirect": fix_open_redirect,
    "Permissive CORS Configuration": fix_cors,
    "Negative / Zero Quantity": fix_negative_quantity,
    "Weak / Broken Cryptography": fix_weak_crypto,
    "Missing Authentication on Sensitive Action": fix_missing_auth,
    "Server-Side Request Forgery (SSRF)": fix_ssrf,
    "XML External Entity (XXE)": fix_xxe,
    "Insecure Deserialization": fix_insecure_deserialization,
    "Server-Side Template Injection": fix_ssti,
    "JWT Verification Weakness": fix_jwt,
    "Mass Assignment / Over-posting": fix_mass_assignment,
    "Hardcoded Secret / Credential": fix_hardcoded_secret,
    "Price / Quantity Manipulation": fix_price_manipulation,
    "Sensitive Action Without Rate Limiting": fix_rate_limit,
    "Reflected Cross-Site Scripting (XSS)": fix_reflected_xss,
    "Sensitive Information Exposure": fix_sensitive_info_exposure,
    "Code Injection": fix_code_injection,
    "Insecure Randomness for Security Value": fix_insecure_randomness,
    # Race Condition is handled by the language-aware lock patcher in healer.py
}


def fix_in_source(vuln_type, src, language):
    fixer = FIXERS.get(vuln_type)
    if fixer is None:
        # Substring-tolerant fallback: the matcher's emitted `type` string is not
        # always byte-identical to a dispatch key (e.g. "Reflected Cross-Site
        # Scripting (XSS)" vs "Cross-Site Scripting"). Match on the most specific
        # signal so a phrasing change never silently disables a fixer.
        t = (vuln_type or "")
        if ("Cross-Site Scripting" in t or "XSS" in t or "Template" in t):
            fixer = fix_reflected_xss
        elif ("Sensitive Information" in t or "Information Disclosure" in t
              or "Information Exposure" in t):
            fixer = fix_sensitive_info_exposure
        elif ("SQL Injection" in t and "NoSQL" not in t):
            fixer = fix_sql_injection
        elif "Deserialization" in t:
            fixer = fix_insecure_deserialization
        elif "Command Injection" in t:
            fixer = fix_command_injection
        elif "Path Traversal" in t:
            fixer = fix_path_traversal
        elif "Rate Limiting" in t:
            fixer = fix_rate_limit
        elif ("Debug Mode" in t or "Insecure Configuration" in t
              or "Verbose Errors" in t):
            fixer = fix_debug_mode
        elif ("Code Injection" in t or "Eval Injection" in t
              or "eval" in t.lower() or "Use of eval" in t):
            fixer = fix_code_injection
        elif ("Randomness" in t or "Insufficiently Random" in t or "Weak Random" in t):
            fixer = fix_insecure_randomness
        elif ("Weak Password Hashing" in t or "Weak Hashing" in t
              or "Weak Cryptography" in t or "Weak Crypto" in t
              or "Broken Cryptography" in t or "MD5" in t
              or "Hash Algorithm" in t):
            fixer = fix_weak_crypto
        elif "Hardcoded" in t or "Hard-coded" in t:
            fixer = fix_hardcoded_secret
        else:
            # match any remaining dispatch key that is a substring of the type
            for key, fn in FIXERS.items():
                if key in t:
                    fixer = fn
                    break
    if fixer is None:
        return None, None
    return fixer(src, language)
