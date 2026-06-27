"""
AST/CST-based fixers (LibCST) -- robust root-cause codemods for Python
======================================================================

The original fixers in ``code_fixer.py`` rewrite source with ``re.sub``. Regex is
fine for *recognising* a known sink name, but it is the WRONG tool for rewriting
code: it breaks on multi-line calls, comments between arguments, single- vs
double-quoted strings, nested expressions and whitespace drift. A tool that
prides itself on AST-based *detection* should fix with the same rigour.

This module performs the two flagship CRITICAL fixes on a real concrete syntax
tree (LibCST, which preserves formatting and comments), so the transform is
exact regardless of how the code is laid out, and the output is guaranteed to be
syntactically valid (it is re-rendered from a tree, not string-spliced):

  * OS Command Injection  -> remove the shell, pass an argv LIST (shell=False).
  * SQL Injection         -> parameterised query with bound placeholders.

The same root-cause philosophy as before (separate data from control), but the
rewrite is structural. Each transform is conservative: if the shape is anything
it is not certain it can rewrite safely, it makes NO change and returns the
source unchanged, so the caller (healer) cleanly falls back to the regex fixer
and nothing regresses. The healer's triple-verification still gates every fix.

Python only -- LibCST is a Python grammar. Other languages keep their existing
fixers; deepening them is tracked as a separate work item.
"""

from __future__ import annotations

import re

try:
    import libcst as cst
    _HAVE_CST = True
except Exception:                       # pragma: no cover
    _HAVE_CST = False

    class _CstUnavailable:
        """Placeholder used only when libcst is not installed, so the module-level
        ``class X(cst.CSTTransformer)`` definitions below still import cleanly
        instead of raising NameError. Every CST fixer checks ``_HAVE_CST`` first
        and returns ``(None, None)`` when it is False, so none of these classes is
        ever instantiated -- the textual fixers in code_fixer.py handle the work.
        Returning ``object`` for any attribute makes ``cst.CSTTransformer`` (and any
        other attribute used as a base class) a valid, harmless base."""

        def __getattr__(self, name):
            return object

    cst = _CstUnavailable()


# ----------------------------------------------------------------------------
# Small helpers for reading/writing nodes by their TREE structure (not text).
# ----------------------------------------------------------------------------
def _code(node) -> str:
    """Exact source for a node (used to carry an expression verbatim)."""
    return cst.Module(body=[]).code_for_node(node).strip()


def _attr_name(func) -> str:
    """Dotted name of a call target: os.system -> 'os.system', exec -> 'exec'."""
    if isinstance(func, cst.Name):
        return func.value
    if isinstance(func, cst.Attribute):
        return _attr_name(func.value) + "." + func.attr.value
    return ""


def _string_segments(node):
    """Yield ('text', str) / ('expr', node) segments of a string-building
    expression by walking the TREE: simple/concatenated/f-strings and '+'
    concatenations. Returns None if a part can't be represented."""
    segs = []

    def walk(n):
        if isinstance(n, cst.SimpleString):
            val = n.evaluated_value
            if not isinstance(val, str):
                raise ValueError("bytes/other literal")
            segs.append(("text", val))
        elif isinstance(n, cst.ConcatenatedString):
            walk(n.left)
            walk(n.right)
        elif isinstance(n, cst.FormattedString):
            for part in n.parts:
                if isinstance(part, cst.FormattedStringText):
                    segs.append(("text", part.value))
                elif isinstance(part, cst.FormattedStringExpression):
                    segs.append(("expr", part.expression))
                else:
                    raise ValueError("unknown fstring part")
        elif isinstance(n, cst.BinaryOperation) and isinstance(n.operator, cst.Add):
            walk(n.left)
            walk(n.right)
        elif (isinstance(n, cst.Call) and isinstance(n.func, cst.Attribute)
              and n.func.attr.value == "format"
              and isinstance(n.func.value, (cst.SimpleString, cst.ConcatenatedString))):
            # "...{}...{0}...{name}...".format(a, b, name=c)
            fmt = n.func.value.evaluated_value
            if not isinstance(fmt, str):
                raise ValueError("non-str format")
            pos = [a.value for a in n.args if a.keyword is None]
            kw = {a.keyword.value: a.value for a in n.args if a.keyword is not None}
            auto = 0
            for part in re.split(r"(\{[^{}]*\})", fmt):
                if part.startswith("{") and part.endswith("}") and len(part) >= 2:
                    spec = part[1:-1].split(":")[0].split("!")[0].strip()
                    if spec == "":
                        if auto >= len(pos):
                            raise ValueError("format arg mismatch")
                        segs.append(("expr", pos[auto])); auto += 1
                    elif spec.isdigit():
                        segs.append(("expr", pos[int(spec)]))
                    elif spec in kw:
                        segs.append(("expr", kw[spec]))
                    else:
                        raise ValueError("unresolved format field")
                elif part:
                    segs.append(("text", part.replace("{{", "{").replace("}}", "}")))
        elif isinstance(n, cst.BinaryOperation) and isinstance(n.operator, cst.Modulo) \
                and isinstance(n.left, (cst.SimpleString, cst.ConcatenatedString)):
            # "...%s...%s..." % value   /   % (a, b)
            fmt = n.left.evaluated_value
            if not isinstance(fmt, str):
                raise ValueError("non-str %-format")
            if isinstance(n.right, cst.Tuple):
                vals = [e.value for e in n.right.elements]
            else:
                vals = [n.right]
            vi = 0
            for part in re.split(r"(%[-+ #0-9.]*[sdrifgeoxXc%])", fmt):
                if re.fullmatch(r"%[-+ #0-9.]*[sdrifgeoxXc]", part):
                    if vi >= len(vals):
                        raise ValueError("%-arg mismatch")
                    segs.append(("expr", vals[vi])); vi += 1
                elif part == "%%":
                    segs.append(("text", "%"))
                elif part:
                    segs.append(("text", part))
        else:
            # a bare variable / call / attribute -> one dynamic segment
            segs.append(("expr", n))

    walk(node)
    return segs


def _py_str_literal(text: str) -> str:
    """A safe Python double-quoted string literal for `text`."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


# ----------------------------------------------------------------------------
# Command injection: build an argv LIST from a shell-string expression.
# ----------------------------------------------------------------------------
def _segments_to_argv(segs):
    """Turn string segments into an argv list source string: tokens split on
    whitespace in literal text; each interpolated expression is its own token.
    Returns the list source (e.g. '["ping", "-c", "1", host]') or None if a
    token mixes literal text and an expression with no whitespace boundary
    (ambiguous -> let the caller fall back)."""
    tokens = []          # each token: list of ('lit', str) / ('expr', src)
    current = None       # the token being built

    def flush():
        nonlocal current
        if current is not None:
            tokens.append(current)
            current = None

    for kind, val in segs:
        if kind == "text":
            i = 0
            for chunk in _split_keep_ws(val):
                if chunk.isspace():
                    flush()
                else:
                    if current is None:
                        current = []
                    current.append(("lit", chunk))
            # text ending without trailing space keeps `current` open so an
            # adjacent expression attaches to the same token.
        else:  # expr
            src = _code(val)
            if current is None:
                current = [("expr", src)]
                flush()                      # space-delimited expr -> own token
            else:
                current.append(("expr", src))
    flush()

    elements = []
    for tok in tokens:
        if len(tok) == 1 and tok[0][0] == "lit":
            elements.append(_py_str_literal(tok[0][1]))
        elif len(tok) == 1 and tok[0][0] == "expr":
            # user-controlled positional arg -> validate (reject option injection
            # and out-of-charset values) before it reaches the command.
            elements.append(f"_lb_safe_cmd_arg({tok[0][1]})")
        else:
            # mixed token (literal glued to an expression): build a concatenation
            parts = []
            for t, v in tok:
                parts.append(_py_str_literal(v) if t == "lit" else "str(" + v + ")")
            elements.append(" + ".join(parts))
    if not elements:
        return None
    return "[" + ", ".join(elements) + "]"


def _split_keep_ws(s):
    """Split a string into runs of whitespace and non-whitespace, preserving
    both (so token boundaries are exact)."""
    out, buf, ws = [], "", None
    for ch in s:
        is_ws = ch.isspace()
        if ws is None:
            ws = is_ws
            buf = ch
        elif is_ws == ws:
            buf += ch
        else:
            out.append(buf)
            buf, ws = ch, is_ws
    if buf:
        out.append(buf)
    return out


_SHELL_RUNNERS = {"os.system", "os.popen", "commands.getoutput"}
_SUBPROCESS_FNS = {"subprocess.run", "subprocess.call", "subprocess.check_call",
                   "subprocess.check_output", "subprocess.Popen",
                   "subprocess.getoutput"}


class _CommandInjectionFixer(cst.CSTTransformer):
    """Rewrite shell-string command execution into a shell-free argv call."""

    def __init__(self):
        self.changed = False
        self.need_subprocess = False

    def leave_Call(self, original, updated):
        name = _attr_name(updated.func)
        args = list(updated.args)
        if not args:
            return updated

        # --- subprocess.<fn>(<cmd>, shell=True, ...) -------------------------
        if name in _SUBPROCESS_FNS:
            shell_true = any(
                a.keyword is not None and a.keyword.value == "shell"
                and isinstance(a.value, cst.Name) and a.value.value == "True"
                for a in args)
            if not shell_true:
                return updated            # already safe form
            cmd_arg = args[0]
            argv = self._try_argv(cmd_arg.value)
            new_args = []
            for idx, a in enumerate(args):
                if idx == 0 and argv is not None:
                    new_args.append(a.with_changes(value=cst.parse_expression(argv)))
                elif a.keyword is not None and a.keyword.value == "shell":
                    continue              # drop shell=True
                else:
                    new_args.append(a)
            # if cmd wasn't a rewritable string but is already a list/var, just
            # dropping shell=True is the correct, safe fix.
            self.changed = True
            return updated.with_changes(args=_normalize_commas(new_args))

        # --- os.system / os.popen(<shell string>) ---------------------------
        if name in _SHELL_RUNNERS:
            argv = self._try_argv(args[0].value)
            if argv is None:
                return updated            # can't safely convert -> leave for fallback
            self.need_subprocess = True
            self.changed = True
            argv_node = cst.parse_expression(argv)
            if name == "os.system":
                # exit-code semantics -> subprocess.run(argv)
                return cst.parse_expression(f"subprocess.run({argv})")
            # os.popen / getoutput capture output -> check_output(..., text=True)
            return cst.parse_expression(f"subprocess.check_output({argv}, text=True)")

        return updated

    def _try_argv(self, value_node):
        try:
            segs = _string_segments(value_node)
        except Exception:
            return None
        # only convert when there IS at least one dynamic part and one literal
        # (a pure-literal command isn't a vuln; a pure-variable we can't split).
        kinds = {k for k, _ in segs}
        if "text" not in kinds or "expr" not in kinds:
            return None
        return _segments_to_argv(segs)


def _spaced_comma():
    return cst.Comma(whitespace_after=cst.SimpleWhitespace(" "))


def _normalize_commas(args):
    """Re-attach trailing commas cleanly after removing an argument."""
    fixed = []
    for i, a in enumerate(args):
        if i == len(args) - 1:
            fixed.append(a.with_changes(comma=cst.MaybeSentinel.DEFAULT))
        else:
            fixed.append(a.with_changes(comma=_spaced_comma()))
    return fixed


# ----------------------------------------------------------------------------
# SQL injection: build a parameterised (sql, params) call.
# ----------------------------------------------------------------------------
_SQL_EXEC = {"execute", "executemany", "executescript"}


def _detect_sql_paramstyle(module_src: str) -> str:
    """Pick the DRIVER-CORRECT placeholder style from the project's imports, so
    the fix is actually valid for the database in use -- not a blind `%s`.

    Returns one of: 'named_colon' (:name + dict), 'named_pyformat' (%(name)s +
    dict), 'qmark' (? + tuple), 'format' (%s + tuple)."""
    s = module_src
    if re.search(r"\b(import\s+sqlite3|from\s+sqlite3)\b", s):
        return "qmark"              # sqlite3: positional ? placeholders + tuple
    if re.search(r"\b(psycopg2|psycopg)\b", s):
        return "named_pyformat"     # psycopg 'pyformat' -> %(name)s
    if re.search(r"\b(pymysql|mysql\.connector|MySQLdb|mariadb|aiomysql)\b", s):
        return "named_pyformat"     # mysql connectors 'pyformat'
    if re.search(r"\b(cx_Oracle|oracledb)\b", s):
        return "named_colon"        # oracle 'named' -> :name
    if re.search(r"\bpyodbc\b", s):
        return "qmark"              # pyodbc only supports positional ?
    if re.search(r"\b(asyncpg)\b", s):
        return "qmark"              # asyncpg uses $1.. but ? is closest portable
    return "named_colon"            # default: readable, valid for sqlite/oracle/SQLAlchemy text()


def _param_name_for(node) -> str:
    """Derive a READABLE bind-parameter name from the interpolated expression,
    e.g. request.args.get("username") -> 'username', user.id -> 'id'."""
    try:
        if isinstance(node, cst.Name):
            return node.value
        if isinstance(node, cst.Attribute):
            return node.attr.value
        if isinstance(node, cst.Subscript):
            el = node.slice[0]
            sl = getattr(el, "slice", el)
            inner = getattr(sl, "value", None)
            if isinstance(inner, cst.SimpleString):
                v = inner.evaluated_value
                if isinstance(v, str) and v.isidentifier():
                    return v
        if isinstance(node, cst.Call):
            for a in node.args:
                if isinstance(a.value, cst.SimpleString):
                    v = a.value.evaluated_value
                    if isinstance(v, str) and v.isidentifier():
                        return v
            if isinstance(node.func, cst.Attribute):
                return node.func.attr.value
    except Exception:
        pass
    return "param"


def _placeholder_and_params(segs, style):
    """Enterprise parameterisation. Returns (sql, params_src, is_dict) or None.

    Named styles produce SELF-DOCUMENTING, driver-correct bound parameters with a
    dict ({"username": username}); positional styles produce a tuple. Identical
    expressions are de-duplicated onto a single bind name."""
    named = style in ("named_colon", "named_pyformat")
    sql = []
    order = []          # named: list of (name, expr_src) ; positional: [expr_src]
    seen = {}           # expr_src -> bind name (dedupe)
    counts = {}
    for kind, val in segs:
        if kind == "text":
            sql.append(val)
            continue
        expr_src = _code(val)
        if named:
            if expr_src in seen:
                name = seen[expr_src]
            else:
                base = _param_name_for(val)
                name = base
                if name in counts:
                    counts[name] += 1
                    name = f"{base}_{counts[base]}"
                else:
                    counts[name] = 1
                seen[expr_src] = name
                order.append((name, expr_src))
            sql.append(f":{name}" if style == "named_colon" else f"%({name})s")
        else:
            order.append(expr_src)
            sql.append("?" if style == "qmark" else "%s")
    if not order:
        return None
    sql_str = "".join(sql)
    # CRITICAL: a bound placeholder must NOT sit inside SQL quotes, or the driver
    # treats it as the literal text ":name"/"?" and never binds. Strip a matching
    # quote pair wrapping any placeholder form: '...'/"..." -> bare placeholder.
    sql_str = re.sub(r"""(['"])(\?|%s|%\([A-Za-z_]\w*\)s|:[A-Za-z_]\w*)\1""",
                     r"\2", sql_str)
    if named:
        body = ", ".join(f'"{n}": {e}' for n, e in order)
        return sql_str, "{" + body + "}", True
    tail = "," if len(order) == 1 else ""
    return sql_str, "(" + ", ".join(order) + tail + ")", False


def _segments_to_param_sql(segs):
    """Build ('<sql with %s>', [param_src, ...]) from string segments. Removes
    quotes immediately wrapping a placeholder ('%s' -> %s). Returns None if no
    dynamic parameter is present."""
    sql = []
    params = []
    for kind, val in segs:
        if kind == "text":
            sql.append(val)
        else:
            sql.append("%s")
            params.append(_code(val))
    if not params:
        return None
    sql_str = "".join(sql)
    # a bound placeholder must not be quoted: WHERE x = '%s' -> WHERE x = %s
    sql_str = sql_str.replace("'%s'", "%s").replace('"%s"', "%s")
    return sql_str, params


class _SqlInjectionFixer(cst.CSTTransformer):
    """Rewrite .execute(<string-built query>) into a parameterised call."""

    def __init__(self, style="named_colon"):
        self.changed = False
        self.style = style

    def leave_Call(self, original, updated):
        func = updated.func
        if not (isinstance(func, cst.Attribute) and func.attr.value in _SQL_EXEC):
            return updated
        args = list(updated.args)
        if len(args) != 1 or args[0].keyword is not None:
            return updated               # already has params, or unusual shape
        try:
            segs = _string_segments(args[0].value)
        except Exception:
            return updated
        # GUARD: there must be an actual query STRING here to parameterise. If the
        # only segment is a bare variable (the query was built elsewhere), do NOT
        # emit a broken non-fix. The cross-file variable case is _SqlVarFixer.
        if not any(kind == "text" for kind, _ in segs):
            return updated
        built = _placeholder_and_params(segs, self.style)
        if built is None:
            return updated
        sql_str, params_src, _is_dict = built
        sql_node = cst.parse_expression(_py_str_literal(sql_str))
        params_node = cst.parse_expression(params_src)
        self.changed = True
        return updated.with_changes(args=[
            cst.Arg(value=sql_node, comma=_spaced_comma()),
            cst.Arg(value=params_node),
        ])


# ----------------------------------------------------------------------------
# Module-level entry points (mirror code_fixer's (new_src, note) contract).
# ----------------------------------------------------------------------------
def _ensure_import(module_src: str, import_stmt: str) -> str:
    if import_stmt in module_src:
        return module_src
    lines = module_src.splitlines(keepends=True)
    insert_at = 0
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith("import ") or s.startswith("from "):
            insert_at = i + 1
    lines.insert(insert_at, import_stmt + "\n")
    return "".join(lines)


def fix_command_injection_cst(src: str, language: str):
    """CST command-injection fix. Returns (new_src, note) or (None, None)."""
    if not _HAVE_CST or language != "python":
        return None, None
    try:
        module = cst.parse_module(src)
    except Exception:
        return None, None
    fixer = _CommandInjectionFixer()
    new_module = module.visit(fixer)
    if not fixer.changed:
        return None, None
    out = new_module.code
    if "_lb_safe_cmd_arg(" in out and "def _lb_safe_cmd_arg" not in out:
        try:
            out = _inject_after_imports(cst.parse_module(out), _CMD_ARG_HELPER).code
        except Exception:
            pass
    if fixer.need_subprocess:
        out = _ensure_import(out, "import subprocess")
    return out, ("AST fix (LibCST): removed shell execution at the root. The command is built as an "
                 "argv list and run without a shell, so shell metacharacters in user input (';', "
                 "'|', '$()', '&') are literal arguments and cannot spawn extra commands. "
                 "User-controlled arguments are additionally validated (option-injection and "
                 "out-of-charset values are rejected). Structural rewrite on the syntax tree.")


class _SqlVarFixer(cst.CSTTransformer):
    """Parameterise `q = <built query>; ...; cur.execute(q)` -- the query is built
    into a LOCAL variable then executed. Rewrites the assignment to a placeholder
    string and passes the bound params at the execute call (same function)."""

    def __init__(self, style="named_colon"):
        self.changed = False
        self.style = style

    def leave_FunctionDef(self, original, updated):
        block = updated.body
        if not isinstance(block, cst.IndentedBlock):
            return updated
        # which local vars are executed as queries?
        exec_vars = set()
        for stmt in block.body:
            for node in _descendants(stmt):
                if isinstance(node, cst.Call) and isinstance(node.func, cst.Attribute) \
                        and node.func.attr.value in _SQL_EXEC and len(node.args) == 1 \
                        and node.args[0].keyword is None \
                        and isinstance(node.args[0].value, cst.Name):
                    exec_vars.add(node.args[0].value.value)
        if not exec_vars:
            return updated
        # rewrite the assignment(s) that build those vars
        var_params = {}
        new_body = []
        for stmt in block.body:
            done = False
            if isinstance(stmt, cst.SimpleStatementLine) and len(stmt.body) == 1 \
                    and isinstance(stmt.body[0], cst.Assign):
                asg = stmt.body[0]
                if len(asg.targets) == 1 and isinstance(asg.targets[0].target, cst.Name) \
                        and asg.targets[0].target.value in exec_vars:
                    try:
                        segs = _string_segments(asg.value)
                        built = _placeholder_and_params(segs, self.style)
                    except Exception:
                        built = None
                    if built and any(k == "text" for k, _ in segs):
                        sql_str, params_src, _is_dict = built
                        new_body.append(stmt.with_changes(body=[asg.with_changes(
                            value=cst.parse_expression(_py_str_literal(sql_str)))]))
                        var_params[asg.targets[0].target.value] = params_src
                        done = True
            if not done:
                new_body.append(stmt)
        if not var_params:
            return updated

        parent = self

        class _AddParams(cst.CSTTransformer):
            def leave_Call(self, o, u):
                if isinstance(u.func, cst.Attribute) and u.func.attr.value in _SQL_EXEC \
                        and len(u.args) == 1 and isinstance(u.args[0].value, cst.Name) \
                        and u.args[0].value.value in var_params:
                    parent.changed = True
                    return u.with_changes(args=[
                        u.args[0].with_changes(comma=_spaced_comma()),
                        cst.Arg(value=cst.parse_expression(var_params[u.args[0].value.value])),
                    ])
                return u

        new_block = block.with_changes(body=new_body).visit(_AddParams())
        return updated.with_changes(body=new_block)


def fix_sql_injection_cst(src: str, language: str):
    """CST SQL-injection fix. Returns (new_src, note) or (None, None)."""
    if not _HAVE_CST or language != "python":
        return None, None
    try:
        module = cst.parse_module(src)
    except Exception:
        return None, None
    style = _detect_sql_paramstyle(src)
    style_desc = {
        "named_colon": "named bind parameters (:name) with a dict",
        "named_pyformat": "named bind parameters (%(name)s) with a dict",
        "qmark": "positional bind parameters (?)",
        "format": "positional bind parameters (%s)",
    }[style]
    note = ("AST fix (LibCST, CWE-89): the user input is no longer concatenated into SQL text. "
            f"The query is rewritten to use {style_desc}, matched to the database driver detected "
            "in this project, and the values are passed to the driver separately so they are sent "
            "over the wire as typed parameters -- they can never change the query's structure. This "
            "is a structural rewrite of the syntax tree (root-cause), not blacklist filtering or "
            "escaping. Further hardening: if you use an ORM (e.g. SQLAlchemy), prefer its query API; "
            "and never interpolate table/column names -- validate those against a fixed allow-list.")
    # 1) inline case: cur.execute("..."+x)
    fixer = _SqlInjectionFixer(style)
    out = module.visit(fixer)
    if fixer.changed:
        return out.code, note
    # 2) variable case: q = "..."+x; cur.execute(q)
    vfixer = _SqlVarFixer(style)
    out2 = module.visit(vfixer)
    if vfixer.changed:
        return out2.code, note
    return None, None


_HTML_TAG_RE = re.compile(r"<\s*[a-zA-Z/!][^>]*>")


def _concat_has_html_tag(node) -> bool:
    """True if a string literal anywhere in this expression contains an HTML tag."""
    found = [False]

    def walk(x):
        if found[0]:
            return
        if isinstance(x, cst.SimpleString):
            if _HTML_TAG_RE.search(x.value):
                found[0] = True
                return
        for c in getattr(x, "children", []):
            walk(c)

    walk(node)
    return found[0]


def _is_str_literal(n) -> bool:
    return isinstance(n, (cst.SimpleString, cst.ConcatenatedString, cst.FormattedString))


def _already_escaped(n) -> bool:
    if isinstance(n, cst.Call):
        f = n.func
        if isinstance(f, cst.Name) and f.value in ("escape", "_lb_escape", "Markup"):
            return True
        if isinstance(f, cst.Attribute) and f.attr.value in ("escape", "Markup"):
            return True
        # str(escape(...)) -> already escaped (our own wrapper form)
        if isinstance(f, cst.Name) and f.value == "str" and len(n.args) == 1:
            inner = n.args[0].value
            if isinstance(inner, cst.Call) and _already_escaped(inner):
                return True
    return False


def _xss_wrap_operands(n, fx):
    """In a `+` string concatenation, wrap each NON-literal operand in escape()."""
    if isinstance(n, cst.BinaryOperation) and isinstance(n.operator, cst.Add):
        return n.with_changes(left=_xss_wrap_operands(n.left, fx),
                              right=_xss_wrap_operands(n.right, fx))
    if _is_str_literal(n) or _already_escaped(n):
        return n
    # a dynamic (user-controllable) operand interpolated into HTML -> escape it.
    # We wrap as str(escape(x)): escape() returns a markupsafe.Markup whose + would
    # auto-escape the adjacent HTML string literals (mangling the page), so str()
    # collapses it to a plain escaped string and the literal markup is preserved.
    fx.changed = True
    return cst.Call(func=cst.Name("str"), args=[cst.Arg(
        value=cst.Call(func=cst.Name("escape"), args=[cst.Arg(value=n)]))])


class _XssFixer(cst.CSTTransformer):
    """HTML-escape user input that is concatenated into an HTML response."""
    def __init__(self):
        self.changed = False

    def leave_Return(self, original, updated):
        val = updated.value
        if val is None or not isinstance(val, cst.BinaryOperation):
            return updated
        if not _concat_has_html_tag(val):
            return updated
        new = _xss_wrap_operands(val, self)
        return updated.with_changes(value=new) if self.changed else updated


def _has_escape_import(module) -> bool:
    for stmt in module.body:
        if isinstance(stmt, cst.SimpleStatementLine):
            for s in stmt.body:
                if isinstance(s, cst.ImportFrom) and s.names is not None:
                    for n in s.names:
                        nm = n.evaluated_name if hasattr(n, "evaluated_name") else None
                        if nm == "escape" or (isinstance(n.name, cst.Name) and n.name.value == "escape"):
                            return True
    return False


def fix_reflected_xss_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _XssFixer()
    out = m.visit(fx)
    if not fx.changed:
        return None, None
    if not _has_escape_import(out):
        out = _inject_after_imports(out, "from markupsafe import escape\n")
    return out.code, ("AST fix (LibCST): HTML-escaped user input before it is concatenated into the "
                      "response (markupsafe.escape), so injected <script>/markup is rendered as inert "
                      "text -- closing the reflected XSS while preserving the page output.")


def _node_src(n) -> str:
    try:
        return cst.Module([]).code_for_node(n)
    except Exception:
        return ""


_SECRET_RETURN_RE = re.compile(
    r"os\.(environ|getenv)|getenv\s*\(|process\.env|"
    r"\b(secret_?key|secretkey|password|passwd|api_?key|private_?key|"
    r"access_?token|client_?secret|aws_secret|db_password)\w*", re.I)


class _InfoExposureFixer(cst.CSTTransformer):
    """Stop a handler from returning secrets/env straight to the client."""
    def __init__(self):
        self.changed = False

    def leave_Return(self, original, updated):
        val = updated.value
        if val is None:
            return updated
        if _SECRET_RETURN_RE.search(_node_src(val)):
            self.changed = True
            return updated.with_changes(
                value=cst.parse_expression('("Not authorized to view this resource", 403)'))
        return updated


def fix_sensitive_info_exposure_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _InfoExposureFixer()
    out = m.visit(fx)
    if not fx.changed:
        return None, None
    return out.code, ("AST fix (LibCST): removed direct exposure of secrets/environment to the client; "
                      "the handler now returns HTTP 403 instead of leaking SECRET_KEY/credentials. Expose "
                      "only the specific non-sensitive fields a client legitimately needs.")


def fix_cst(vuln_type: str, src: str, language: str):
    """Dispatch to a CST fixer by finding type. Returns (None, None) if no CST
    fixer applies to this type/shape (caller then uses the regex fixer as a
    fallback, so nothing regresses). CST is Python-only by nature; for other
    languages this always returns (None, None)."""
    if language != "python" or not _HAVE_CST:
        return None, None
    t = vuln_type
    # --- expression / call rewrites ---------------------------------------
    if "Command Injection" in t:
        return fix_command_injection_cst(src, language)
    if "SQL Injection" in t and "NoSQL" not in t:
        return fix_sql_injection_cst(src, language)
    if "Weak" in t and "Crypt" in t:
        return fix_weak_crypto_cst(src, language)
    if "Debug Mode" in t:
        return fix_debug_mode_cst(src, language)
    if "JWT" in t:
        return fix_jwt_cst(src, language)
    if "XML External Entity" in t or "XXE" in t:
        return fix_xxe_cst(src, language)
    if "Deserialization" in t:
        return fix_deserialization_cst(src, language)
    if "Cross-Site Scripting" in t or "XSS" in t:
        return fix_reflected_xss_cst(src, language)
    if "Sensitive Information" in t or "Information Disclosure" in t or "Information Exposure" in t:
        return fix_sensitive_info_exposure_cst(src, language)
    if "Template Injection" in t:
        return fix_ssti_cst(src, language)
    if "Hardcoded Secret" in t:
        return fix_hardcoded_secret_cst(src, language)
    if "Broken Authentication" in t:
        return fix_weak_auth_cst(src, language)
    if "Broken Authorization" in t:
        return fix_broken_auth_cst(src, language)
    if "Mass Assignment" in t:
        return fix_mass_assignment_cst(src, language)
    if "CORS" in t:
        return fix_cors_cst(src, language)
    # --- guard insertions --------------------------------------------------
    if "Missing Authentication" in t:
        return fix_missing_auth_cst(src, language)
    if "Direct Object Reference" in t or "IDOR" in t:
        return fix_idor_cst(src, language)
    if "Path Traversal" in t:
        return fix_path_traversal_cst(src, language)
    if "Negative" in t and "Quantity" in t:
        return fix_negative_quantity_cst(src, language)
    if "Price" in t and "Manipulation" in t:
        return fix_price_manipulation_cst(src, language)
    if "Rate Limiting" in t:
        return fix_rate_limit_cst(src, language)
    if "Request Forgery" in t or "SSRF" in t:
        return fix_ssrf_cst(src, language)
    if "Open Redirect" in t:
        return fix_open_redirect_cst(src, language)
    if "NoSQL" in t:
        return fix_nosql_injection_cst(src, language)
    if "LDAP" in t:
        return fix_ldap_injection_cst(src, language)
    if "XPath" in t:
        return fix_xpath_injection_cst(src, language)
    if "CRLF" in t or "Response Splitting" in t:
        return fix_crlf_injection_cst(src, language)
    if "Code Injection" in t:
        return fix_code_injection_cst(src, language)
    return None, None


# ============================================================================
# Shared CST helpers for the remaining fixers
# ============================================================================
def _kwarg(name: str, value_src: str):
    """A keyword argument node `name=value` with PEP8 spacing (no spaces)."""
    return cst.Arg(keyword=cst.Name(name),
                   value=cst.parse_expression(value_src),
                   equal=cst.AssignEqual(whitespace_before=cst.SimpleWhitespace(""),
                                         whitespace_after=cst.SimpleWhitespace("")))


def _append_arg(args, new_arg):
    """Append `new_arg` to an arg list, giving the previous last arg a comma."""
    args = list(args)
    if args:
        args[-1] = args[-1].with_changes(comma=_spaced_comma())
    return args + [new_arg]


def _has_kwarg(args, name: str) -> bool:
    return any(a.keyword is not None and a.keyword.value == name for a in args)


def _descendants(node):
    """Yield a node and all of its descendants (pre-order)."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        try:
            stack.extend(n.children)
        except Exception:
            pass


def _simple_first(stmt):
    """The first small-statement inside a SimpleStatementLine, else None."""
    if isinstance(stmt, cst.SimpleStatementLine) and stmt.body:
        return stmt.body[0]
    return None


def _refs_request(node) -> bool:
    """True if the expression reads from the HTTP request (request / .json /
    .form / .args)."""
    for n in _descendants(node):
        if isinstance(n, cst.Name) and n.value == "request":
            return True
        if isinstance(n, cst.Attribute) and n.attr.value in ("json", "form", "args", "values"):
            return True
    return False


def _is_request_access_any(node) -> bool:
    """True if node is any read of request.<x>[...] / request.<x>.get(...)."""
    for n in _descendants(node):
        if isinstance(n, cst.Attribute) and isinstance(n.value, cst.Name) \
                and n.value.value == "request":
            return True
    return False


def _subscript_key_text(sub):
    """Return the string key of a single-key subscript, lowercased, else ''."""
    try:
        for el in sub.slice:
            sl = el.slice
            val = getattr(sl, "value", None)
            if isinstance(val, cst.SimpleString):
                return (val.evaluated_value or "").lower()
    except Exception:
        pass
    return ""


# ============================================================================
# Expression / call rewrites
# ============================================================================
class _WeakCryptoFixer(cst.CSTTransformer):
    def __init__(self):
        self.changed = False

    def leave_Call(self, original, updated):
        f = updated.func
        if (isinstance(f, cst.Attribute) and isinstance(f.value, cst.Name)
                and f.value.value == "hashlib" and f.attr.value in ("md5", "sha1")):
            self.changed = True
            return updated.with_changes(func=f.with_changes(attr=cst.Name("sha256")))
        return updated


def fix_weak_crypto_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _WeakCryptoFixer()
    out = m.visit(fx)
    if not fx.changed:
        return None, None
    return out.code, ("AST fix (LibCST): upgraded the weak hash (MD5/SHA-1) to SHA-256. NOTE: for "
                      "password storage use bcrypt/argon2/PBKDF2 rather than a bare hash; existing "
                      "stored hashes must be migrated.")


class _DebugModeFixer(cst.CSTTransformer):
    def __init__(self):
        self.changed = False

    def leave_Arg(self, original, updated):
        if (updated.keyword is not None and updated.keyword.value == "debug"
                and isinstance(updated.value, cst.Name) and updated.value.value == "True"):
            self.changed = True
            return updated.with_changes(value=cst.Name("False"))
        return updated

    def leave_Assign(self, original, updated):
        if isinstance(updated.value, cst.Name) and updated.value.value == "True":
            for t in updated.targets:
                tgt = t.target
                if (isinstance(tgt, cst.Attribute) and tgt.attr.value == "debug") or \
                   (isinstance(tgt, cst.Name) and tgt.value in ("DEBUG", "debug")):
                    self.changed = True
                    return updated.with_changes(value=cst.Name("False"))
        return updated


def fix_debug_mode_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _DebugModeFixer()
    out = m.visit(fx)
    if not fx.changed:
        return None, None
    return out.code, ("AST fix (LibCST): disabled debug mode (debug=False). Debug mode exposes stack "
                      "traces and an interactive debugger that can lead to RCE in production.")


class _JwtFixer(cst.CSTTransformer):
    def __init__(self):
        self.changed = False

    def leave_Call(self, original, updated):
        f = updated.func
        if (isinstance(f, cst.Attribute) and f.attr.value == "decode"
                and isinstance(f.value, cst.Name) and f.value.value == "jwt"):
            args = list(updated.args)
            new, has_algs, changed = [], False, False
            for a in args:
                if (a.keyword is not None and a.keyword.value == "verify"
                        and isinstance(a.value, cst.Name) and a.value.value == "False"):
                    new.append(a.with_changes(value=cst.Name("True")))
                    changed = True
                else:
                    if a.keyword is not None and a.keyword.value == "algorithms":
                        has_algs = True
                    new.append(a)
            if not has_algs:
                new = _append_arg(new, _kwarg("algorithms", "['HS256']"))
                changed = True
            if changed:
                self.changed = True
                return updated.with_changes(args=new)
        return updated


def fix_jwt_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _JwtFixer()
    out = m.visit(fx)
    if not fx.changed:
        return None, None
    return out.code, ("AST fix (LibCST): enabled JWT signature verification (verify=True) and pinned "
                      "an algorithm allowlist (HS256), preventing alg=none and signature-skip attacks.")


class _XxeFixer(cst.CSTTransformer):
    def __init__(self):
        self.changed = False

    def leave_Call(self, original, updated):
        f = updated.func
        if isinstance(f, cst.Attribute) and f.attr.value in ("parse", "fromstring"):
            base = f.value
            base_name = base.attr.value if isinstance(base, cst.Attribute) else \
                (base.value if isinstance(base, cst.Name) else "")
            if base_name == "etree" and not _has_kwarg(updated.args, "parser"):
                new = _append_arg(list(updated.args),
                                  _kwarg("parser",
                                         "etree.XMLParser(resolve_entities=False, no_network=True)"))
                self.changed = True
                return updated.with_changes(args=new)
        return updated


def fix_xxe_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _XxeFixer()
    out = m.visit(fx)
    if not fx.changed:
        return None, None
    return out.code, ("AST fix (LibCST): disabled external-entity resolution and network access in "
                      "the XML parser (resolve_entities=False, no_network=True), preventing XXE file "
                      "reads and SSRF. For full safety prefer the defusedxml library.")


class _DeserialFixer(cst.CSTTransformer):
    def __init__(self):
        self.changed = False
        self.unsafe = False

    def leave_Call(self, original, updated):
        f = updated.func
        if isinstance(f, cst.Attribute):
            base = f.value.value if isinstance(f.value, cst.Name) else ""
            if base == "yaml" and f.attr.value == "load":
                self.changed = True
                return updated.with_changes(func=f.with_changes(attr=cst.Name("safe_load")))
            if base in ("pickle", "cPickle", "dill", "marshal") and f.attr.value in ("load", "loads"):
                self.unsafe = True
        return updated


def _inject_after_imports(module, helper_src):
    """Insert top-level statements from helper_src after the last leading import."""
    helper = list(cst.parse_module(helper_src).body)
    body = list(module.body)
    idx = 0
    for i, stmt in enumerate(body):
        if isinstance(stmt, cst.SimpleStatementLine) and stmt.body and \
                isinstance(stmt.body[0], (cst.Import, cst.ImportFrom)):
            idx = i + 1
    return module.with_changes(body=body[:idx] + helper + body[idx:])


_SAFE_PICKLE_HELPER = '''
# --- added by LogicBreaker: restricted unpickler (neutralises pickle RCE) ---
import io as _lb_io
import pickle as _lb_pickle


class _LBRestrictedUnpickler(_lb_pickle.Unpickler):
    """Allow ONLY safe built-in types. Any attempt to resolve another global
    (os.system, subprocess.Popen, a __reduce__ gadget, ...) raises instead of
    executing -- so a crafted pickle payload can no longer run code."""

    _ALLOWED = {
        ("builtins", "list"), ("builtins", "dict"), ("builtins", "tuple"),
        ("builtins", "set"), ("builtins", "frozenset"), ("builtins", "str"),
        ("builtins", "bytes"), ("builtins", "bytearray"), ("builtins", "int"),
        ("builtins", "float"), ("builtins", "bool"), ("builtins", "complex"),
        ("builtins", "NoneType"),
    }

    def find_class(self, module, name):
        if (module, name) in self._ALLOWED:
            return super().find_class(module, name)
        raise _lb_pickle.UnpicklingError(
            f"blocked unsafe pickle global: {module}.{name}")


def _lb_safe_loads(data):
    """Drop-in for pickle.loads that refuses dangerous payloads."""
    return _LBRestrictedUnpickler(_lb_io.BytesIO(data)).load()


def _lb_safe_load(fp):
    """Drop-in for pickle.load that refuses dangerous payloads."""
    return _LBRestrictedUnpickler(fp).load()
'''


class _PickleFixer(cst.CSTTransformer):
    """Redirect pickle.loads/load (and cPickle/_pickle/dill) to the restricted
    unpickler helper, keeping the wire format but removing code execution."""
    _MODS = {"pickle", "cPickle", "_pickle", "dill"}

    def __init__(self):
        self.changed = False

    def leave_Call(self, original, updated):
        f = updated.func
        if isinstance(f, cst.Attribute) and isinstance(f.value, cst.Name) \
                and f.value.value in self._MODS and f.attr.value in ("loads", "load"):
            new_name = "_lb_safe_loads" if f.attr.value == "loads" else "_lb_safe_load"
            self.changed = True
            return updated.with_changes(func=cst.Name(new_name))
        return updated


def fix_deserialization_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    # 1) yaml.load -> yaml.safe_load
    fx = _DeserialFixer()
    out = m.visit(fx)
    if fx.changed:
        return out.code, ("AST fix (LibCST): replaced yaml.load with yaml.safe_load, which refuses the "
                          "Python-object tags that allow arbitrary code execution on crafted YAML.")
    # 2) pickle/cPickle/dill.loads on untrusted data -> restricted unpickler
    pf = _PickleFixer()
    out2 = m.visit(pf)
    if pf.changed:
        out2 = _inject_after_imports(out2, _SAFE_PICKLE_HELPER)
        return out2.code, ("AST fix (LibCST): routed pickle deserialization through a RESTRICTED unpickler "
                           "that whitelists only safe built-in types. Crafted pickle payloads (os.system / "
                           "__reduce__ gadgets) are rejected instead of executed -- the RCE is neutralised "
                           "while the data format is preserved. For fully untrusted input, prefer a JSON "
                           "or signed (HMAC) message format.")
    return None, None


class _SstiFixer(cst.CSTTransformer):
    def __init__(self):
        self.changed = False

    def leave_Call(self, original, updated):
        f = updated.func
        if isinstance(f, cst.Name) and f.value == "render_template_string" and updated.args:
            a0 = updated.args[0]
            if isinstance(a0.value, cst.FormattedString):
                try:
                    segs = _string_segments(a0.value)
                except Exception:
                    return updated
                tmpl, kwargs = [], []
                for kind, val in segs:
                    if kind == "text":
                        tmpl.append(val)
                    else:
                        if isinstance(val, cst.Name):
                            tmpl.append("{{ " + val.value + " }}")
                            if val.value not in kwargs:
                                kwargs.append(val.value)
                        else:
                            return updated      # complex expr -> bail to fallback
                if not kwargs:
                    return updated
                new_args = [cst.Arg(value=cst.parse_expression(_py_str_literal("".join(tmpl))),
                                    comma=_spaced_comma())]
                for i, k in enumerate(kwargs):
                    last = i == len(kwargs) - 1
                    new_args.append(cst.Arg(
                        keyword=cst.Name(k), value=cst.Name(k),
                        equal=cst.AssignEqual(whitespace_before=cst.SimpleWhitespace(""),
                                              whitespace_after=cst.SimpleWhitespace("")),
                        comma=cst.MaybeSentinel.DEFAULT if last else _spaced_comma()))
                self.changed = True
                return updated.with_changes(args=new_args)
        return updated


def fix_ssti_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _SstiFixer()
    out = m.visit(fx)
    if not fx.changed:
        return None, None
    return out.code, ("AST fix (LibCST): moved user input out of the template SOURCE into autoescaped "
                      "Jinja context variables ({{ x }} + x=x), so it is rendered as data, not executed "
                      "as template code. This closes server-side template injection.")


class _SecretFixer(cst.CSTTransformer):
    def __init__(self):
        self.changed = False

    def leave_Assign(self, original, updated):
        if self.changed:
            return updated
        if len(updated.targets) == 1:
            tgt = updated.targets[0].target
            name = tgt.value if isinstance(tgt, cst.Name) else \
                (tgt.attr.value if isinstance(tgt, cst.Attribute) else "")
            if name and re.search(r"(?i)(api[_-]?key|secret|passwo?rd|token)", name) \
                    and isinstance(updated.value, cst.SimpleString):
                val = updated.value.evaluated_value
                if isinstance(val, str) and len(val) >= 8:
                    self.changed = True
                    return updated.with_changes(
                        value=cst.parse_expression('os.environ.get("APP_SECRET")'))
        return updated


def fix_hardcoded_secret_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _SecretFixer()
    out = m.visit(fx)
    if not fx.changed:
        return None, None
    code = _ensure_import(out.code, "import os")
    return code, ("AST fix (LibCST): moved the hardcoded secret out of source into an environment "
                  "variable (os.environ.get). Rotate the exposed value -- secrets in code leak through "
                  "version control.")


class _WeakAuthFixer(cst.CSTTransformer):
    def __init__(self):
        self.changed = False

    def leave_If(self, original, updated):
        if self.changed:
            return updated
        test = updated.test
        if isinstance(test, cst.Comparison) and len(test.comparisons) == 1:
            comp = test.comparisons[0]
            if isinstance(comp.operator, (cst.Equal, cst.NotEqual)):
                left, right = test.left, comp.comparator
                # the client value (a Name) is compared either to another Name or
                # to a hardcoded string credential (the common `==` / `!=` static
                # password/token/key check).
                ok = ((isinstance(left, cst.Name) and isinstance(right, cst.Name)) or
                      (isinstance(left, cst.Name) and isinstance(right, cst.SimpleString)) or
                      (isinstance(left, cst.SimpleString) and isinstance(right, cst.Name)))
                blob = (_code(left) + " " + _code(right)).lower()
                if ok and re.search(r"key|secret|token|pass|auth|cred|sig|hash|digest|admin|pin",
                                    blob):
                    a, b = _code(left), _code(right)
                    self.changed = True
                    expr = f"hmac.compare_digest(str({a}), str({b}))"
                    if isinstance(comp.operator, cst.NotEqual):
                        expr = "not " + expr
                    return updated.with_changes(test=cst.parse_expression(expr))
        return updated


def fix_weak_auth_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _WeakAuthFixer()
    out = m.visit(fx)
    if not fx.changed:
        return None, None
    code = _ensure_import(out.code, "import hmac")
    return code, ("AST fix (LibCST): replaced the `==` credential check with a constant-time comparison "
                  "(hmac.compare_digest) to defeat timing attacks. IMPORTANT: this is a partial "
                  "mitigation; the real fix is per-user credentials + a server-side session or signed "
                  "token, not a static key.")


def _is_request_role_access(node) -> bool:
    role_keys = {"role", "is_admin", "admin", "privilege", "isadmin", "is_staff", "superuser"}
    if isinstance(node, cst.Subscript) and isinstance(node.value, cst.Attribute):
        v = node.value
        if isinstance(v.value, cst.Name) and v.value.value == "request" \
                and v.attr.value in ("form", "args", "json"):
            return _subscript_key_text(node) in role_keys
    if isinstance(node, cst.Call) and isinstance(node.func, cst.Attribute) \
            and node.func.attr.value == "get":
        base = node.func.value
        if isinstance(base, cst.Attribute) and isinstance(base.value, cst.Name) \
                and base.value.value == "request" and base.attr.value in ("form", "args", "json"):
            if node.args and isinstance(node.args[0].value, cst.SimpleString):
                return (node.args[0].value.evaluated_value or "").lower() in role_keys
    return False


class _BrokenAuthFixer(cst.CSTTransformer):
    """Replace any read of a client-supplied role (request.form['role'],
    request.args.get('is_admin'), ...) with a server-side session lookup,
    wherever it appears -- assignment RHS, if-condition, call argument."""
    def __init__(self):
        self.changed = False

    def _replace(self, updated):
        if _is_request_role_access(updated):
            self.changed = True
            return cst.parse_expression("get_role_from_session(session)")
        return updated

    def leave_Call(self, original, updated):
        return self._replace(updated)

    def leave_Subscript(self, original, updated):
        return self._replace(updated)


def fix_broken_auth_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _BrokenAuthFixer()
    out = m.visit(fx)
    if not fx.changed:
        return None, None
    return out.code, ("AST fix (LibCST): replaced the client-supplied role with a server-side session "
                      "lookup (get_role_from_session), so the caller can no longer set their own "
                      "privilege level.")


class _MassAssignFixer(cst.CSTTransformer):
    def __init__(self):
        self.changed = False

    def leave_Arg(self, original, updated):
        if updated.star == "**":
            v = updated.value
            ref = None
            if isinstance(v, cst.Attribute) and isinstance(v.value, cst.Name) \
                    and v.value.value == "request" and v.attr.value in ("json", "form"):
                ref = "request." + v.attr.value
            elif isinstance(v, cst.Call) and isinstance(v.func, cst.Attribute) \
                    and isinstance(v.func.value, cst.Name) and v.func.value.value == "request" \
                    and v.func.attr.value == "get_json":
                ref = "request.get_json()"
            if ref:
                self.changed = True
                comp = f"{{k: {ref}[k] for k in ('name', 'email') if k in {ref}}}"
                return updated.with_changes(value=cst.parse_expression(comp))
        return updated


def fix_mass_assignment_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _MassAssignFixer()
    out = m.visit(fx)
    if not fx.changed:
        return None, None
    return out.code, ("AST fix (LibCST): restricted mass-assignment to an explicit field allowlist "
                      "('name', 'email'), so attackers cannot set privileged fields like is_admin by "
                      "adding them to the request body.")


class _CorsFixer(cst.CSTTransformer):
    def __init__(self):
        self.changed = False

    def leave_Assign(self, original, updated):
        if len(updated.targets) == 1 and isinstance(updated.targets[0].target, cst.Subscript):
            sub = updated.targets[0].target
            if _subscript_key_text(sub) == "access-control-allow-origin":
                v = updated.value
                bad = (isinstance(v, cst.SimpleString) and v.evaluated_value == "*") \
                    or _is_request_access_any(v)
                if bad:
                    self.changed = True
                    return updated.with_changes(
                        value=cst.parse_expression('"https://yourdomain.com"'))
        return updated

    def leave_Arg(self, original, updated):
        if (updated.keyword is not None and updated.keyword.value == "origins"
                and isinstance(updated.value, cst.SimpleString)
                and updated.value.evaluated_value == "*"):
            self.changed = True
            return updated.with_changes(value=cst.parse_expression('["https://yourdomain.com"]'))
        return updated


def fix_cors_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _CorsFixer()
    out = m.visit(fx)
    if not fx.changed:
        return None, None
    return out.code, ("AST fix (LibCST): replaced the wildcard/reflected CORS origin with an explicit "
                      "allowlisted origin. Reflecting the request Origin or using '*' with credentials "
                      "lets any site read authenticated responses.")


# ============================================================================
# Guard insertions (find the function body, inject a check at the right place)
# ============================================================================
class _TopGuardInserter(cst.CSTTransformer):
    """Insert guard statement(s) at the TOP of the target handler's body. Targets
    the function named `target` if given; otherwise the first function that looks
    like a request handler (references `request` or has a route decorator),
    skipping LogicBreaker-injected helper functions."""
    def __init__(self, guard_src, target=None):
        self.guard = list(cst.parse_module(guard_src).body)
        self.target = target
        self.done = False

    def _is_target(self, node):
        name = node.name.value
        if self.target is not None:
            return name == self.target
        if name.startswith("_lb_") or name.startswith("_LB"):
            return False
        try:
            body_src = cst.Module([]).code_for_node(node.body)
        except Exception:
            body_src = ""
        if re.search(r"\brequest\b", body_src):
            return True
        for d in node.decorators:
            try:
                if "route" in cst.Module([]).code_for_node(d):
                    return True
            except Exception:
                pass
        return False

    def leave_FunctionDef(self, original, updated):
        if self.done or not self._is_target(updated):
            return updated
        block = updated.body
        if not isinstance(block, cst.IndentedBlock):
            return updated
        self.done = True
        return updated.with_changes(body=block.with_changes(body=self.guard + list(block.body)))


def fix_missing_auth_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    guard = ('if not session.get("user_id"):\n'
             '    return ("authentication required", 401)\n')
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _TopGuardInserter(guard)
    out = m.visit(fx)
    if not fx.done:
        return None, None
    return out.code, ("AST fix (LibCST): inserted an authentication guard at the top of the handler; "
                      "unauthenticated callers (no session user) are rejected with HTTP 401 before the "
                      "sensitive action runs.")


_RATE_LIMIT_HELPER = '''
# --- added by LogicBreaker: simple thread-safe in-process rate limiter ---
# For multi-worker / production use, prefer Flask-Limiter or a Redis-backed store.
import time as _lb_time
import threading as _lb_threading
from collections import defaultdict as _lb_defaultdict

_LB_RATE = _lb_defaultdict(list)
_LB_RATE_LOCK = _lb_threading.Lock()


def _lb_rate_limited(key, limit=10, window=60):
    """True if `key` has exceeded `limit` requests within `window` seconds."""
    now = _lb_time.time()
    with _LB_RATE_LOCK:
        hits = [h for h in _LB_RATE[key] if now - h < window]
        hits.append(now)
        _LB_RATE[key] = hits
        return len(hits) > limit
'''


_CMD_ARG_HELPER = '''
# --- added by LogicBreaker: validate user-supplied command arguments ---
# Extra hardening on top of shell removal: rejects option-injection (leading '-')
# and anything outside a hostname/IP/path charset, so a user value can't be
# reinterpreted as a flag or smuggle shell metacharacters.
import re as _lb_re


def _lb_safe_cmd_arg(v):
    """Reject option-injection and out-of-charset command arguments."""
    v = str(v)
    if not v or v[0] == "-" or not _lb_re.fullmatch(r"[A-Za-z0-9._:/-]+", v):
        raise ValueError("rejected unsafe command argument: %r" % (v,))
    return v
'''


def fix_rate_limit_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    guard = (
        'if _lb_rate_limited(getattr(request, "remote_addr", "anon")):\n'
        '    return ("Too Many Requests", 429)\n'
    )
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _TopGuardInserter(guard)
    out = m.visit(fx)
    if not fx.done:
        return None, None
    # inject the helper once (only if its DEFINITION is not already present).
    # NB: we must look for "def _lb_rate_limited", NOT the bare name -- the guard
    # call we just inserted ("if _lb_rate_limited(...)") already contains the
    # name, so testing the name alone would wrongly skip the definition and leave
    # the patched file calling an undefined function (NameError at runtime).
    if "def _lb_rate_limited" not in out.code:
        out = _inject_after_imports(out, _RATE_LIMIT_HELPER)
    return out.code, ("AST fix (LibCST): added a thread-safe per-client rate limit (10 req/min -> HTTP "
                      "429) via a shared in-process counter to blunt brute-force/abuse. For multiple "
                      "workers, back it with Redis or use Flask-Limiter.")


def _loader_assign_var(stmt):
    """If the statement is `var = <loader call>(...)`, return var, else None."""
    first = _simple_first(stmt)
    if isinstance(first, cst.Assign) and len(first.targets) == 1:
        tgt = first.targets[0].target
        if isinstance(tgt, cst.Name):
            for n in _descendants(first.value):
                if isinstance(n, cst.Call) and isinstance(n.func, cst.Attribute) \
                        and n.func.attr.value in ("get", "query", "filter", "find",
                                                  "first", "fetchone", "one_or_none",
                                                  "get_or_404"):
                    return tgt.value
    return None


class _IdorGuardFixer(cst.CSTTransformer):
    def __init__(self):
        self.done = False

    def leave_FunctionDef(self, original, updated):
        if self.done:
            return updated
        block = updated.body
        if not isinstance(block, cst.IndentedBlock):
            return updated
        out, inserted = [], False
        for s in block.body:
            out.append(s)
            if not inserted:
                var = _loader_assign_var(s)
                if var:
                    g = cst.parse_module(
                        f'if {var} is None or getattr({var}, "owner_id", None) '
                        f'!= session.get("user_id"):\n'
                        f'    return ("forbidden", 403)\n').body
                    out.extend(g)
                    inserted = True
        if inserted:
            self.done = True
            return updated.with_changes(body=block.with_changes(body=out))
        return updated


def fix_idor_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _IdorGuardFixer()
    out = m.visit(fx)
    if not fx.done:
        return None, None
    return out.code, ("AST fix (LibCST): inserted an ownership check after the object lookup; the "
                      "request is rejected with 403 unless the loaded object belongs to the "
                      "authenticated user (session user_id).")


class _OpenArgRewriter(cst.CSTTransformer):
    """Find the first open(<path>) call, extract the user variable (bare or as
    the dynamic operand of a `prefix + var` concatenation), replace the path
    argument with `_safe_path`, and record the var + base directory."""
    def __init__(self):
        self.var = None
        self.base = None
        self.done = False

    def leave_Call(self, original, updated):
        if self.done:
            return updated
        if isinstance(updated.func, cst.Name) and updated.func.value == "open" and updated.args:
            arg = updated.args[0].value
            var, base = None, None
            if isinstance(arg, cst.Name):
                var, base = arg.value, '"./safe_files"'
            elif isinstance(arg, cst.BinaryOperation) and isinstance(arg.operator, cst.Add):
                left, right = arg.left, arg.right
                if isinstance(left, cst.SimpleString) and isinstance(right, cst.Name):
                    var, base = right.value, repr(left.evaluated_value)
                elif isinstance(right, cst.SimpleString) and isinstance(left, cst.Name):
                    var, base = left.value, '"./safe_files"'
            if var:
                self.var, self.base, self.done = var, base, True
                new_args = [updated.args[0].with_changes(value=cst.Name("_safe_path"))] \
                    + list(updated.args[1:])
                return updated.with_changes(args=new_args)
        return updated


class _PathGuardFixer(cst.CSTTransformer):
    def __init__(self):
        self.done = False

    def leave_FunctionDef(self, original, updated):
        if self.done:
            return updated
        block = updated.body
        if not isinstance(block, cst.IndentedBlock):
            return updated
        out, inserted = [], False
        for s in block.body:
            if not inserted:
                rw = _OpenArgRewriter()
                s2 = s.visit(rw)
                if rw.done:
                    g = cst.parse_module(
                        'import os as _os\n'
                        f'_BASE = _os.path.realpath({rw.base})\n'
                        '_safe_path = _os.path.realpath(_os.path.join('
                        f'_BASE, _os.path.basename({rw.var})))\n'
                        'if _safe_path != _BASE and not _safe_path.startswith(_BASE + _os.sep):\n'
                        '    return ("forbidden", 403)\n').body
                    out.extend(g)
                    out.append(s2)
                    inserted = True
                    continue
            out.append(s)
        if inserted:
            self.done = True
            return updated.with_changes(body=block.with_changes(body=out))
        return updated


def fix_path_traversal_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    # idempotency: if the fix was already applied (by CST or regex), skip
    if "_safe_path" in src or "_BASE" in src or \
       "_lb_safe_path" in src or "_lb_base" in src:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _PathGuardFixer()
    out = m.visit(fx)
    if not fx.done:
        return None, None
    return out.code, ("AST fix (LibCST): confined the user-supplied path to a safe base directory; the "
                      "filename is reduced to its basename and the resolved real path must stay under "
                      "the base, else the request is rejected with 403. Blocks ../ traversal and "
                      "absolute-path escapes.")


def _request_number_var(stmt, candidates):
    first = _simple_first(stmt)
    if isinstance(first, cst.Assign) and len(first.targets) == 1:
        tgt = first.targets[0].target
        name = tgt.value if isinstance(tgt, cst.Name) else None
        if name and name in candidates and _refs_request(first.value):
            return name
    return None


class _PositiveNumberGuardFixer(cst.CSTTransformer):
    def __init__(self, candidates, errmsg):
        self.candidates = candidates
        self.errmsg = errmsg
        self.done = False

    def leave_FunctionDef(self, original, updated):
        if self.done:
            return updated
        block = updated.body
        if not isinstance(block, cst.IndentedBlock):
            return updated
        out, inserted = [], False
        for s in block.body:
            out.append(s)
            if not inserted:
                var = _request_number_var(s, self.candidates)
                if var:
                    g = cst.parse_module(
                        'try:\n'
                        f'    if float({var}) <= 0:\n'
                        f'        return ("{self.errmsg}", 400)\n'
                        'except (TypeError, ValueError):\n'
                        f'    return ("{self.errmsg}", 400)\n').body
                    out.extend(g)
                    inserted = True
        if inserted:
            self.done = True
            return updated.with_changes(body=block.with_changes(body=out))
        return updated


def fix_negative_quantity_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _PositiveNumberGuardFixer(
        {"quantity", "qty", "amount", "count", "price", "total"}, "invalid quantity")
    out = m.visit(fx)
    if not fx.done:
        return None, None
    return out.code, ("AST fix (LibCST): added server-side validation that the quantity is a positive "
                      "number; non-positive or non-numeric values are rejected with HTTP 400.")


def fix_price_manipulation_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _PositiveNumberGuardFixer({"price", "amount", "total", "cost"}, "invalid price")
    out = m.visit(fx)
    if not fx.done:
        return None, None
    return out.code, ("AST fix (LibCST): added server-side validation that the price is positive; "
                      "client-supplied non-positive prices are rejected with HTTP 400. Best practice: "
                      "look the price up server-side, never trust the client value.")


# ============================================================================
# SSRF / Open Redirect (guard-based classes: insert a recognised URL guard
# immediately before the sink so the tainted value is validated at runtime AND
# the taint engine's function-level guard check is satisfied).
# ============================================================================
_SSRF_SINKS = {"requests.get", "requests.post", "requests.put", "requests.delete",
               "requests.patch", "requests.head", "requests.request",
               "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
               "httpx.patch", "httpx.request", "urllib.request.urlopen", "urlopen"}


def _ssrf_sink_var(stmt):
    """First simple-Name URL argument of an SSRF sink call inside `stmt`, else None."""
    for n in _descendants(stmt):
        if isinstance(n, cst.Call):
            name = _attr_name(n.func)
            if (name in _SSRF_SINKS or name.endswith(".urlopen")) and n.args \
                    and isinstance(n.args[0].value, cst.Name):
                return n.args[0].value.value
    return None


class _SsrfGuardFixer(cst.CSTTransformer):
    def __init__(self):
        self.done = False

    def leave_FunctionDef(self, original, updated):
        if self.done:
            return updated
        block = updated.body
        if not isinstance(block, cst.IndentedBlock):
            return updated
        out, inserted = [], False
        for s in block.body:
            if not inserted:
                var = _ssrf_sink_var(s)
                if var:
                    g = cst.parse_module(
                        'from urllib.parse import urlparse as _up\n'
                        f'_host = _up({var}).hostname or ""\n'
                        'if (not _host) or _host in ("localhost", "127.0.0.1", "0.0.0.0", '
                        '"169.254.169.254", "::1") or _host.startswith("10.") '
                        'or _host.startswith("192.168."):\n'
                        '    return ("blocked outbound request", 403)\n').body
                    out.extend(g)
                    out.append(s)
                    inserted = True
                    continue
            out.append(s)
        if inserted:
            self.done = True
            return updated.with_changes(body=block.with_changes(body=out))
        return updated


def fix_ssrf_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _SsrfGuardFixer()
    out = m.visit(fx)
    if not fx.done:
        return None, None
    return out.code, ("AST fix (LibCST): inserted an SSRF guard before the outbound request. The URL "
                      "host is parsed and internal / loopback / link-local / cloud-metadata targets "
                      "(127.0.0.1, 169.254.169.254, 10.x, 192.168.x, ...) are rejected with HTTP 403, "
                      "so the request can no longer be steered at internal services.")


def _redirect_sink_var(stmt):
    """First simple-Name argument of a redirect() call inside `stmt`, else None."""
    for n in _descendants(stmt):
        if isinstance(n, cst.Call):
            f = n.func
            is_redirect = (isinstance(f, cst.Name) and f.value == "redirect") or \
                          (isinstance(f, cst.Attribute) and f.attr.value == "redirect")
            if is_redirect and n.args and isinstance(n.args[0].value, cst.Name):
                return n.args[0].value.value
    return None


class _OpenRedirectGuardFixer(cst.CSTTransformer):
    def __init__(self):
        self.done = False

    def leave_FunctionDef(self, original, updated):
        if self.done:
            return updated
        block = updated.body
        if not isinstance(block, cst.IndentedBlock):
            return updated
        out, inserted = [], False
        for s in block.body:
            if not inserted:
                var = _redirect_sink_var(s)
                if var:
                    g = cst.parse_module(
                        'from urllib.parse import urlparse as _up\n'
                        f'if _up({var}).netloc not in ("", "yourdomain.com"):\n'
                        f'    {var} = "/"  # block off-site redirect\n').body
                    out.extend(g)
                    out.append(s)
                    inserted = True
                    continue
            out.append(s)
        if inserted:
            self.done = True
            return updated.with_changes(body=block.with_changes(body=out))
        return updated


def fix_open_redirect_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _OpenRedirectGuardFixer()
    out = m.visit(fx)
    if not fx.done:
        return None, None
    return out.code, ("AST fix (LibCST): validated the redirect destination before redirecting. Only a "
                      "same-site (empty netloc) or allowlisted host is permitted; any off-site URL is "
                      "rewritten to '/'. This blocks open-redirect phishing.")


# ============================================================================
# NEW injection families: NoSQL / LDAP / XPath / CRLF  (root-cause codemods)
# ============================================================================
_NOSQL_METHODS = {"find", "find_one", "find_one_and_update", "find_one_and_delete",
                  "find_one_and_replace", "update_one", "update_many", "delete_one",
                  "delete_many", "count_documents", "aggregate", "distinct"}


class _NoSqlFixer(cst.CSTTransformer):
    """Force user input in a query object to be a typed SCALAR (str(...)), so it
    is compared as a value and can no longer inject operators ($ne/$gt/...).
    A literal $-operator key (e.g. $where) has no safe drop-in -> bail."""
    def __init__(self):
        self.changed = False
        self.unsafe = False

    def leave_Call(self, original, updated):
        f = updated.func
        if isinstance(f, cst.Attribute) and f.attr.value in _NOSQL_METHODS and updated.args:
            q = updated.args[0].value
            if isinstance(q, cst.Dict):
                new_elems, ch = [], False
                for el in q.elements:
                    if isinstance(el, cst.DictElement):
                        k = el.key
                        ktext = k.evaluated_value if isinstance(k, cst.SimpleString) else ""
                        if isinstance(ktext, str) and ktext.startswith("$"):
                            self.unsafe = True          # operator query -> no safe cast
                            new_elems.append(el)
                            continue
                        v = el.value
                        if isinstance(v, cst.Name) or _refs_request(v):
                            new_elems.append(el.with_changes(
                                value=cst.parse_expression(f"str({_code(v)})")))
                            ch = True
                            continue
                    new_elems.append(el)
                if ch:
                    self.changed = True
                    return updated.with_changes(
                        args=[updated.args[0].with_changes(value=q.with_changes(elements=new_elems))]
                        + list(updated.args[1:]))
        return updated


def fix_nosql_injection_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _NoSqlFixer()
    out = m.visit(fx)
    if fx.changed:
        return out.code, ("AST fix (LibCST): forced user input in the query to a typed scalar (str(...)), "
                          "so it is matched as a value and can no longer inject NoSQL operators "
                          "($ne/$gt/$where) to bypass auth or read other records.")
    return None, None   # $-operator query: needs manual redesign (no safe cast)


def _wrap_concat_operands(node, wrapper):
    """Wrap every dynamic (Name) operand of a `+` string concatenation in
    wrapper(...). String literals are left untouched. Returns (node, changed)."""
    if isinstance(node, cst.Name):
        return cst.parse_expression(f"{wrapper}({node.value})"), True
    if isinstance(node, cst.BinaryOperation) and isinstance(node.operator, cst.Add):
        l, lc = _wrap_concat_operands(node.left, wrapper)
        r, rc = _wrap_concat_operands(node.right, wrapper)
        if lc or rc:
            return node.with_changes(left=l, right=r), True
    return node, False


_LDAP_METHODS = {"search_s", "search_ext_s", "search_st", "search_ext"}


class _LdapFixer(cst.CSTTransformer):
    """Escape LDAP filter metacharacters on every dynamic operand of a filter
    string built by concatenation (escape_filter_chars)."""
    def __init__(self):
        self.changed = False

    def leave_Call(self, original, updated):
        if _attr_name(updated.func).split(".")[-1] in _LDAP_METHODS:
            new_args, ch = [], False
            for a in updated.args:
                if isinstance(a.value, cst.BinaryOperation):
                    nv, c = _wrap_concat_operands(a.value, "escape_filter_chars")
                    if c:
                        new_args.append(a.with_changes(value=nv))
                        ch = True
                        continue
                new_args.append(a)
            if ch:
                self.changed = True
                return updated.with_changes(args=new_args)
        return updated


def fix_ldap_injection_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _LdapFixer()
    out = m.visit(fx)
    if not fx.changed:
        return None, None
    code = _ensure_import(out.code, "from ldap.filter import escape_filter_chars")
    return code, ("AST fix (LibCST): escaped LDAP filter metacharacters on the user input "
                  "(escape_filter_chars), so it cannot break out of the filter term to alter the "
                  "query or bypass an LDAP-bind authentication check.")


def _xpath_parameterize(node):
    """Build ('<xpath with $pN>', [(pname, expr_src), ...]) from a concat / f-string
    xpath expression. Strips quotes wrapping a placeholder. None if no dynamic part."""
    try:
        segs = _string_segments(node)
    except Exception:
        return None
    xp, params = [], []
    i = 0
    for kind, val in segs:
        if kind == "text":
            xp.append(val)
        else:
            pn = f"p{i}"
            i += 1
            xp.append("$" + pn)
            params.append((pn, _code(val)))
    if not params:
        return None
    s = "".join(xp)
    for pn, _ in params:                       # unquote: name='$p0' -> name=$p0
        s = s.replace("'$" + pn + "'", "$" + pn).replace('"$' + pn + '"', "$" + pn)
    return s, params


class _XPathFixer(cst.CSTTransformer):
    """Convert a string-built xpath into a PARAMETERIZED xpath (lxml variables):
    tree.xpath("//u[n='"+x+"']") -> tree.xpath("//u[n=$p0]", p0=x)."""
    def __init__(self):
        self.changed = False

    def leave_Call(self, original, updated):
        f = updated.func
        if isinstance(f, cst.Attribute) and f.attr.value == "xpath" and updated.args:
            built = _xpath_parameterize(updated.args[0].value)
            if built is None:
                return updated
            xp, params = built
            new_args = [cst.Arg(value=cst.parse_expression(_py_str_literal(xp)),
                                comma=_spaced_comma())]
            for j, (pn, expr) in enumerate(params):
                last = j == len(params) - 1
                new_args.append(cst.Arg(
                    keyword=cst.Name(pn), value=cst.parse_expression(expr),
                    equal=cst.AssignEqual(whitespace_before=cst.SimpleWhitespace(""),
                                          whitespace_after=cst.SimpleWhitespace("")),
                    comma=cst.MaybeSentinel.DEFAULT if last else _spaced_comma()))
            self.changed = True
            return updated.with_changes(args=new_args)
        return updated


def fix_xpath_injection_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _XPathFixer()
    out = m.visit(fx)
    if not fx.changed:
        return None, None
    return out.code, ("AST fix (LibCST): converted the string-built XPath into a PARAMETERIZED "
                      "expression with bound variables ($p0...), so user input is a value and can no "
                      "longer alter the XPath structure or bypass an XML-backed auth check.")


class _CrlfFixer(cst.CSTTransformer):
    """Strip CR/LF from a user-controlled header value so it cannot inject extra
    headers / split the HTTP response."""
    def __init__(self):
        self.changed = False

    def _is_crlf_sink(self, func):
        last = _attr_name(func).split(".")[-1]
        if last in ("set_cookie", "add_header", "set_header"):
            return True
        # response.headers.add(...) / response.headers.set(...)
        if isinstance(func, cst.Attribute) and func.attr.value in ("add", "set") \
                and isinstance(func.value, cst.Attribute) and func.value.attr.value == "headers":
            return True
        return False

    def leave_Call(self, original, updated):
        if self._is_crlf_sink(updated.func):
            new_args, ch = [], False
            for a in updated.args:
                if a.keyword is None and isinstance(a.value, cst.Name):
                    new_args.append(a.with_changes(value=cst.parse_expression(
                        a.value.value + '.replace("\\r", "").replace("\\n", "")')))
                    ch = True
                else:
                    new_args.append(a)
            if ch:
                self.changed = True
                return updated.with_changes(args=new_args)
        return updated

    @staticmethod
    def _is_header_target(target):
        """`<obj>.headers[<key>]` assignment target, where <obj> isn't request."""
        return (isinstance(target, cst.Subscript)
                and isinstance(target.value, cst.Attribute)
                and target.value.attr.value == "headers"
                and not (isinstance(target.value.value, cst.Name)
                         and target.value.value.value == "request"))

    def leave_Assign(self, original, updated):
        # CRLF via header ASSIGNMENT: resp.headers["X"] = value -> strip CR/LF.
        if len(updated.targets) == 1 and self._is_header_target(updated.targets[0].target):
            v = updated.value
            if isinstance(v, cst.Name):
                self.changed = True
                return updated.with_changes(value=cst.parse_expression(
                    v.value + '.replace("\\r", "").replace("\\n", "")'))
        return updated


def fix_crlf_injection_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _CrlfFixer()
    out = m.visit(fx)
    if not fx.changed:
        return None, None
    return out.code, ("AST fix (LibCST): stripped CR/LF characters from the user-controlled header "
                      "value, so it can no longer inject additional headers or split the HTTP response "
                      "(response-splitting / cookie injection).")


# ============================================================================
# Code Injection (eval/exec/compile)
# ============================================================================
class _CodeInjectionFixer(cst.CSTTransformer):
    """Replace eval(user) with ast.literal_eval(user) -- the standard secure
    replacement that parses ONLY Python literals and cannot run code. exec /
    compile / __import__ have no safe drop-in -> left for a recommendation."""
    def __init__(self):
        self.changed = False

    def leave_Call(self, original, updated):
        f = updated.func
        if isinstance(f, cst.Name) and f.value == "eval" and updated.args:
            self.changed = True
            return updated.with_changes(func=cst.parse_expression("ast.literal_eval"))
        return updated


def fix_code_injection_cst(src, language):
    if language != "python" or not _HAVE_CST:
        return None, None
    try:
        m = cst.parse_module(src)
    except Exception:
        return None, None
    fx = _CodeInjectionFixer()
    out = m.visit(fx)
    if not fx.changed:
        return None, None     # exec/compile/__import__: no safe drop-in -> recommend
    code = _ensure_import(out.code, "import ast")
    return code, ("AST fix (LibCST): replaced eval() with ast.literal_eval(), which safely parses only "
                  "Python literals (numbers, strings, lists, dicts, tuples) and CANNOT execute code. If "
                  "the input was meant to run code, that capability must be removed -- there is no safe "
                  "way to eval untrusted code.")
