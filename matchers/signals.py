"""
Cross-language signal helpers
=============================

Matchers need to ask questions like "does this function check a value and
then mutate it after a blocking call?" or "is this parameter used in a SQL
string without parameterization?" across many languages. Re-deriving that
from each grammar's AST is impractical for 40+ languages, so these helpers
work on the function's *source text* using language-aware tables of
keywords, operators, and call patterns.

This is intentionally a heuristic layer. Every finding it produces is scored
with a confidence, and -- where possible -- promoted to CONFIRMED only by the
dynamic exploitation stage. The goal is high-signal triage across many
languages, not a formal proof from static analysis alone.
"""

import re

# Blocking / latency calls per language (the genuine "time-of-use" gap in a
# TOCTOU race). These must be operations that actually yield/await or perform
# slow I/O between the check and the update -- NOT every method call. A bare
# `->query(` or `.find(` is far too common in normal code to count.
BLOCKING_CALLS = {
    "python": ["time.sleep(", "asyncio.sleep(", "await ", "session.commit(",
               ".commit()", "subprocess.", "requests.get(", "requests.post(",
               ".execute(", ".query(", ".fetchone(", ".fetchall(", ".first(",
               ".all(", ".save(", ".get("],
    "javascript": ["await ", "setTimeout(", ".then(", "new Promise(",
                   "fs.readFileSync(", "execSync("],
    "typescript": ["await ", "setTimeout(", ".then(", "new Promise("],
    "tsx": ["await "],
    "java": ["Thread.sleep(", "wait(", ".get()", "Future", ".join("],
    "go": ["time.Sleep(", "<-", ".Wait()", "time.After("],
    "php": ["sleep(", "usleep(", "->commit(", "->beginTransaction(", "curl_exec(",
            "file_get_contents(", "fwrite("],
    "ruby": ["sleep(", ".commit", "Thread."],
    "c_sharp": ["Thread.Sleep(", "Task.Delay(", "await ", ".Wait()", ".Result"],
}

# Tokens that indicate a numeric comparison guard.
COMPARE_OPERATORS = [">=", "<=", ">", "<", "==", "!="]

# SQL sink calls per language.
SQL_SINKS = {
    "python": ["execute(", "executemany(", "raw(", "cursor.execute("],
    "javascript": [".query(", ".raw(", ".execute("],
    "typescript": [".query(", ".raw(", ".execute("],
    "java": ["createStatement(", "executeQuery(", "executeUpdate(", "prepareStatement("],
    "go": [".Query(", ".Exec(", ".QueryRow("],
    "php": ["mysqli_query(", "->query(", "->exec(", "pg_query(", "mysql_query(",
            #  WordPress $wpdb methods -- without these, WP plugin SQLi via
            # $wpdb->get_results/get_var/get_row/get_col was missed.
            "->get_results(", "->get_var(", "->get_row(", "->get_col(",
            "->replace(", "->insert(", "->update(", "->delete("],
    "ruby": [".execute(", ".where(", "find_by_sql("],
    "c_sharp": ["SqlCommand(", "ExecuteReader(", "ExecuteNonQuery("],
}

# String concatenation operators per language (for SQLi heuristics).
CONCAT_TOKENS = {
    "python": ["+", "%", ".format(", "f\"", "f'"],
    "javascript": ["+", "`", "${"],
    "typescript": ["+", "`", "${"],
    "java": ["+"],
    "go": ["+", "fmt.Sprintf("],
    "php": [".", "\"$", "'$"],
    "ruby": ["#{", "+"],
    "c_sharp": ["+", "$\"", "string.Format("],
}

# Authn/authz mutation/role tokens.
ROLE_TOKENS = ["is_admin", "isadmin", "role", "is_superuser", "permission",
               "privilege", "grant_role", "grant_admin", "grant_access",
               "access_level", "user_type", "is_staff", "is_root"]

# Lock / synchronization primitives per language.
LOCK_TOKENS = {
    "python": ["lock", "rlock", "semaphore", "with self._lock", "threading.lock",
               "select_for_update", "for update"],
    "javascript": ["mutex", "lock(", "transaction(", "serializable"],
    "typescript": ["mutex", "lock(", "transaction(", "serializable"],
    "java": ["synchronized", "reentrantlock", "lock()", "select ... for update",
             "for update", "@transactional"],
    "go": ["sync.mutex", ".lock()", "mutex", "tx.", "for update"],
    "php": ["lock", "for update", "begintransaction", "->transaction"],
    "ruby": ["mutex", "with_lock", "lock!", "transaction", "for update"],
    "c_sharp": ["lock(", "semaphore", "monitor.enter", "[synchronized]", "for update"],
}


def lower(s):
    return s.lower() if s else ""


def has_blocking_call(source: str, language: str) -> str:
    src = source
    for token in BLOCKING_CALLS.get(language, ["sleep(", "await ", ".query(", ".execute("]):
        if token in src:
            return token
    return ""


def has_comparison_guard(source: str) -> str:
    """
    Detect a REAL numeric comparison guard used in a conditional -- e.g.
    `if ($balance >= $amount)`. This deliberately excludes:
      * PHP/JS arrow operators `=>` and method/`->` access
      * Go/Rust channel ops and generics `<T>`
      * comparisons that are not inside an if/while/ternary guard
    so that array literals (`'k' => 'v'`), method calls (`$this->x`), and type
    hints don't get mistaken for a check-then-act guard.
    """
    code = _strip_doc_and_comments(source, "")
    # neutralise arrow operators and access tokens BEFORE scanning
    code = code.replace("=>", "  ").replace("->", "  ").replace("<=>", "   ")
    code = code.replace(">=", " GE ").replace("<=", " LE ")
    code = code.replace("==", " EQ ").replace("!=", " NE ")

    # look for a comparison operator that has an operand on BOTH sides and that
    # appears within (or right after) a conditional keyword.
    # match: if/while/elseif/ternary ... <operand> <op> <operand>
    guard_re = re.compile(
        r"\b(?:if|elseif|while|when|unless)\b[^\n{;]*?"
        r"(?:\bGE\b|\bLE\b|(?<![\w>])>(?![=>])|(?<![\w<])<(?![=<]))",
    )
    if guard_re.search(code):
        # report a representative operator
        for tok, disp in (("GE", ">="), ("LE", "<="), (">", ">"), ("<", "<")):
            if tok in code:
                return disp
    # also allow a standalone numeric comparison inside a ternary: `x > y ?`
    if re.search(r"[\w\)\]]\s*(?:GE|LE|>|<)\s*[\w\(\$][^\n]*\?", code):
        return ">"
    return ""


def _strip_comments(source: str, language: str) -> str:
    """Remove comments and string literals so keyword checks don't match text
    inside comments/docstrings (e.g. the word 'lock' in '# no lock here')."""
    s = source
    # line comments
    s = re.sub(r"#.*", "", s)            # python/ruby/php/shell
    s = re.sub(r"//.*", "", s)           # c-family/js/go/java
    # block comments
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
    # triple-quoted docstrings
    s = re.sub(r'""".*?"""', "", s, flags=re.DOTALL)
    s = re.sub(r"'''.*?'''", "", s, flags=re.DOTALL)
    # ordinary string literals (so 'lock' inside a message doesn't count)
    s = re.sub(r'"[^"\n]*"', '""', s)
    s = re.sub(r"'[^'\n]*'", "''", s)
    return s


_TOCTOU_BASEVAR_RE = re.compile(r"[A-Za-z_$][\w$]*")
_FILE_CHECK_RE = re.compile(
    r"\b(?:file_exists|is_file|is_dir|is_writable|is_readable|is_link|realpath|"
    r"stat|lstat|fstat|access|os\.path\.exists|os\.path\.isfile|os\.access|"
    r"Files\.exists|Files\.isReadable|Files\.isWritable|->exists\s*\()\s*\(",
    re.IGNORECASE)
_FILE_MODIFY_RE = re.compile(
    r"\b(?:fopen|file_put_contents|unlink|rename|mkdir|rmdir|chmod|chown|symlink|"
    r"copy|move_uploaded_file|touch|fwrite|os\.remove|os\.rename|os\.open|os\.mkdir|"
    r"shutil\.(?:move|copy|rmtree)|Files\.(?:write|delete|move|copy|newOutputStream)|"
    r"open\s*\(\s*[^,)]+,\s*['\"]?[wa])\s*\(?",
    re.IGNORECASE)


def _toctou_base(tok: str) -> str:
    """Reduce an operand to a comparable resource name. For member access
    (self.balance, $this->_framedepth) use the LAST member so different members
    are treated as different resources; for a plain variable use its name."""
    t = (tok or "").replace("->", ".")
    parts = re.findall(r"[A-Za-z_$][\w$]*", t)
    return parts[-1].lstrip("$") if parts else ""


def detect_toctou(source: str, language: str) -> str:
    """Return the genuine TOCTOU pattern present, or "".

    Only two patterns are real check-then-act-on-a-shared-resource races:
      * 'balance' -- a numeric guard on a value (`if balance >= amount`) followed
        by a numeric mutation of the SAME value (`balance -= amount`, or a
        write-back setter using it arithmetically). The latency window is a
        blocking call between the two.
      * 'file' -- a file-state check (file_exists / is_writable / access ...)
        followed by a file-modifying operation on the path (fopen / unlink /
        rename / chmod ...): the gap between check and use IS the race.

    Everything else (string building with conditionals, status-code checks,
    socket loops in network clients) is NOT a TOCTOU and returns "".
    """
    code = _strip_doc_and_comments(source, language)

    # ---- file-system check-then-act -----------------------------------
    # Only a security-relevant race when the path is externally influenced (a
    # parameter or request source); a client reading its own fixed/local files
    # (e.g. an HTTP client preparing an upload) is not an attacker race.
    cm = _FILE_CHECK_RE.search(code)
    mm = _FILE_MODIFY_RE.search(code)
    if cm and mm and cm.start() < mm.start():
        if _UNTRUSTED_SOURCE_RE.search(code):
            return "file"

    # ---- numeric balance / quota check-then-decrement -----------------
    # The guard must be a one-shot conditional (`if`/`elseif`/`unless`), NOT a
    # loop: a `while (len > 0) { len -= n }` byte/buffer counter in a network
    # client is iteration, not a check-then-act-on-shared-state race.
    c = (code.replace("=>", "  ").replace("->", ".")
             .replace(">=", " > ").replace("<=", " < ")
             .replace("==", "  ").replace("!=", "  "))
    compared = set()
    for m in re.finditer(
            r"\b(?:if|elseif|elif|unless)\b[^\n{;:]*?"
            r"([A-Za-z_$][\w$.\[\]]*)\s*[<>]\s*([A-Za-z_$0-9][\w$.\[\]]*)", c):
        for g in (m.group(1), m.group(2)):
            if g and not g[0].isdigit():
                compared.add(_toctou_base(g))
    if compared:
        # numeric compound assignment to a compared variable, NOT inside a loop
        for m in re.finditer(r"([A-Za-z_$][\w$.\[\]]*)\s*[-+*/]=\s*[^=]", code):
            if _toctou_base(m.group(1)) in compared:
                # reject if the decrement sits inside a while/for loop body
                pre = code[:m.start()]
                if not re.search(r"\b(?:while|for|foreach)\b[^\n{;]*$",
                                 pre.rsplit("\n", 1)[-1]):
                    return "balance"
        # write-back via setter / persistence using the compared var arithmetically
        for cv in compared:
            if not cv:
                continue
            if re.search(r"(?:set_\w+|save|update|update_\w+|decrement|increment|"
                         r"\.save|\.update)\s*\([^)]*\b" + re.escape(cv) +
                         r"\b[^)]*[-+]", code, re.IGNORECASE):
                return "balance"
    return ""


def has_lock(source: str, language: str) -> bool:
    s = lower(_strip_comments(source, language))
    for token in LOCK_TOKENS.get(language, ["lock", "mutex", "synchronized", "for update", "transaction"]):
        if token in s:
            return True
    return False


def mutates_state(source: str, language: str) -> bool:
    """Heuristic: does the body actually WRITE BACK to a field/attribute?
    Requires an assignment or compound-assignment operator on an attribute or
    subscript target -- not merely the presence of a field name."""
    patterns = [
        r"self\.\w+\s*[-+*/]?=[^=]",          # python  self.x = / -=
        r"this\.\w+\s*[-+*/]?=[^=]",          # js/ts/java/c#
        r"\$this->\w+\s*[-+*/]?=[^=]",        # php
        r"\b\w+\.\w+\s*[-+*/]=[^=]",          # receiver.field -= (go etc.)
        r"@\w+\s*[-+*/]?=[^=]",               # ruby ivar
        r"\w+\[[^\]]+\]\s*[-+*/]?=[^=]",      # dict/array subscript write
        r"\b\w+\s*[-+]=[^=]",                 # local -= / += (balance -= amount)
        # state mutation via a SETTER call or persistence/DB write (not a plain
        # assignment) -- e.g. set_balance(...), .save(), .update(), UPDATE ... SET
        r"\bset_\w+\s*\(", r"\.save\s*\(", r"\.update\s*\(", r"\.create\s*\(",
        r"\.decrement\b", r"\.increment\b", r"\bUPDATE\s+\w+\s+SET\b",
        r"\bINSERT\s+INTO\b", r"\.insert\s*\(", r"\.delete\s*\(",
    ]
    for p in patterns:
        if re.search(p, source, re.IGNORECASE):
            return True
    return False


def has_sql_sink(source: str, language: str) -> str:
    for sink in SQL_SINKS.get(language, ["execute(", ".query("]):
        if sink in source:
            return sink
    return ""


def looks_concatenated_sql(source: str, language: str) -> bool:
    """
    Precise SQLi heuristic. A real SQL-injection requires:
      (1) a SQL keyword that sits INSIDE a string literal, and
      (2) that string being concatenated / interpolated with a *variable*.

    We strip comments and docstrings first so that SQL keywords appearing in
    explanations, regex patterns, or token tables do not trigger a finding.
    A SQL keyword that appears only in a comment, a regex, or a standalone
    constant string (no variable concatenation) is NOT flagged.
    """
    # 1) remove comments + docstrings so prose/explanations don't match
    code = _strip_doc_and_comments(source, language)

    # 2) find string literals that contain a *real SQL statement*, not just a
    #    word like "Select" used in UI text. Require SQL structure.
    sql_kw = re.compile(
        r"\bSELECT\b[\s\S]*\bFROM\b"          # SELECT ... FROM
        r"|\bINSERT\s+INTO\b"
        r"|\bUPDATE\b[\s\S]*\bSET\b"          # UPDATE ... SET
        r"|\bDELETE\s+FROM\b"
        r"|\bFROM\b[\s\S]*\bWHERE\b"          # FROM ... WHERE
        r"|\bWHERE\b[\s\S]*[=<>]",            # WHERE <col> = ...
        re.IGNORECASE)

    # python/JS/Java style double/single quoted, f-strings, AND JS/TS backtick
    # template literals (which interpolate with ${...}).
    string_literals = re.findall(
        r'`(?:[^`\\]|\\.)*`'                              # backtick template literal
        r'|(?:f|r|b)?"(?:[^"\\]|\\.)*"'                   # double-quoted
        r"|(?:f|r|b)?'(?:[^'\\]|\\.)*'",                  # single-quoted
        code)
    sql_strings = [s for s in string_literals if sql_kw.search(s)]
    if not sql_strings:
        return False

    # 3) is any SQL string dynamically built with a variable?
    for lit in sql_strings:
        # backtick template literal with ${...} interpolation
        if lit.startswith("`") and re.search(r"\$\{[^}]+\}", lit):
            return True
        # f-string / template interpolation inside the SQL literal
        if re.match(r'^f["\']', lit) and re.search(r"\{[^}]+\}", lit):
            return True
        # generic ${...} / #{...} interpolation, BUT ignore trusted framework
        # table-name properties and constants. A query that only interpolates
        # things like $wpdb->comments (an internal table name) or a numeric/
        # quoted constant is NOT user-controlled injection.
        interps = re.findall(r"\$\{[^}]+\}|#\{[^}]+\}|\$\w+(?:->\w+)?", lit)
        for it in interps:
            inner = it.strip("${}#")
            # trusted: framework db handle table properties (wpdb->comments, etc.)
            if re.match(r"^(wpdb|db|pdo|conn|connection|self|this)\s*->\s*\w+$", inner):
                continue
            # trusted: a table/prefix-looking property only
            if re.search(r"->(comments|posts|users|options|table|prefix|\w*table\w*)$", inner):
                continue
            # otherwise an interpolated variable in SQL is dangerous
            return True

    # concatenation/format directly adjacent to a SQL-bearing literal. We must
    # NOT flag unrelated string concatenation elsewhere in the function (e.g.
    # building an email body), so we look only at the text immediately around
    # each SQL string for `<sqlstring> . $var` / `$var . <sqlstring>` etc.
    for lit in sql_strings:
        try:
            idx = code.index(lit)
        except ValueError:
            continue
        # window: a little before and after this specific SQL string
        before = code[max(0, idx - 40):idx]
        after = code[idx + len(lit): idx + len(lit) + 40]
        # var concatenated right after the SQL string: "... " . $var  /  + var
        if re.search(r"^\s*(\.|\+)\s*\$?[A-Za-z_]\w*", after):
            # exclude trailing concat with another quoted constant only
            if not re.search(r"^\s*(\.|\+)\s*['\"]", after):
                return True
        # var concatenated right before the SQL string: $var . "SELECT ..."
        if re.search(r"\$?[A-Za-z_]\w*\s*(\.|\+)\s*$", before):
            return True
        # printf/format style: sprintf("... WHERE x = %s ...", $var)
        if re.search(r"(sprintf|printf|format|%s|%d)", lit, re.IGNORECASE) and \
           re.search(r"^\s*,\s*\$?[A-Za-z_]\w*", after):
            return True

    return False


def _strip_doc_and_comments(source: str, language: str) -> str:
    """Remove comments AND docstrings, but KEEP ordinary string literals
    (so we can still inspect query strings). Used by SQL/command heuristics."""
    s = source
    # triple-quoted docstrings (python) - remove entirely
    s = re.sub(r'"""(?:.|\n)*?"""', "", s)
    s = re.sub(r"'''(?:.|\n)*?'''", "", s)
    # block comments (c-family)
    s = re.sub(r"/\*(?:.|\n)*?\*/", "", s)
    # line comments
    s = re.sub(r"#.*", "", s)
    # `//` and `--` are line comments in c-family / SQL / lua, but NOT in
    # python/ruby -- where `//` appears inside URLs ("https://x") and `--`
    # inside CLI args ("--flag"). Stripping them there corrupts real code.
    if language not in ("python", "ruby"):
        s = re.sub(r"//.*", "", s)
    if language in ("sql", "lua", "haskell", "ada"):
        s = re.sub(r"--.*", "", s)
    # drop ONLY lines that DEFINE a regex/sink CATALOG (assignment to a list /
    # tuple / regex-string), not ordinary code that merely mentions these words
    # (e.g. a user variable named `token` or `pattern`).
    out = []
    for line in s.splitlines():
        low = line.lower()
        if re.search(r"re\.(compile|search|match|findall|sub)\s*\(", line):
            continue
        if re.search(r"\b(pattern|regex|signatures?|sql_kw|sinks?|tokens?)\w*\s*=\s*[\[\(r]['\"\[\(]?", low):
            continue
        out.append(line)
    return "\n".join(out)


def is_parameterized(source: str) -> bool:
    """Detect parameterized-query placeholders that make SQLi unlikely.

    hardening: %s is a DUAL token -- it's BOTH a Python/PHP format specifier
    (in sprintf / % formatting, which is VULNERABLE) AND a parameterized query
    placeholder (in psycopg2's cursor.execute("...%s", (val,)), which is SAFE).
    The difference is structural:
      - SAFE:    execute("SELECT ... WHERE id = %s", (val,))   <- %s + separate params arg
      - VULN:    sprintf("SELECT ... WHERE id = '%s'", $val)    <- %s inside sprintf/format
      - VULN:    "SELECT ... WHERE id = %s" % val               <- %s with % operator

    We now require the %s to be followed by a SEPARATE params argument (a comma
    + a tuple/list/var) for it to count as parameterized. A bare %s inside
    sprintf() or % formatting is NOT parameterized.
    """
    # prepare() with bound params is always safe
    if re.search(r"->prepare\s*\(", source) or "preparestatement" in source.lower():
        return True
    # ? placeholder with a separate params arg: execute("...?", (val,))
    if re.search(r"\?\s*[,)]\s*\(", source) or re.search(r"\?\s*,\s*\$?\w", source):
        return True
    # :name placeholder (SQLAlchemy) is always parameterized
    if re.search(r":\w+\s*[,)]", source):
        return True
    # $N placeholder (pg-promise, PostgreSQL) is always parameterized
    if re.search(r"\$\d+\s*[,)]", source):
        return True
    # @name placeholder (ADO.NET / SQL Server) is always parameterized
    if re.search(r"@\w+\s*[,)]", source):
        return True
    # %s / %d ONLY counts as parameterized when followed by a SEPARATE params
    # argument (a tuple/list/var after a comma), NOT when it's inside sprintf()
    # or used with the % operator. We must exclude sprintf/format contexts.
    for m in re.finditer(r"%[sdbf]", source):
        # check what comes AFTER the %s
        after = source[m.end():m.end() + 40]
        # if there's a comma + a variable/tuple, it might be parameterized
        if re.match(r"\s*,\s*[\(\[]?\s*\$?\w", after):
            # but if the line contains sprintf/printf/format, the %s is a FORMAT
            # specifier, not a prepared statement placeholder
            line_start = source.rfind("\n", 0, m.start()) + 1
            line = source[line_start:source.find("\n", m.end())]
            if re.search(r"\b(sprintf|printf|vsprintf|fprintf|format)\s*\(", line):
                continue  # format function -> NOT parameterized
            # also check if %s is used with the % operator (Python): "...%s" % val
            if re.search(r"['\"]\s*\%\s*\w", line):
                continue  # % operator -> NOT parameterized
            return True
    return False


# numeric-cast patterns per language: a value converted to a number can no longer
# carry SQL operators or shell metacharacters, so a concatenated cast value is safe.
_CAST_PATTERNS = {
    "python":     [r"\bint\s*\(", r"\bfloat\s*\("],
    "javascript": [r"\bparseInt\s*\(", r"\bparseFloat\s*\(", r"\bNumber\s*\("],
    "typescript": [r"\bparseInt\s*\(", r"\bparseFloat\s*\(", r"\bNumber\s*\("],
    "tsx":        [r"\bparseInt\s*\(", r"\bparseFloat\s*\(", r"\bNumber\s*\("],
    "php":        [r"\bintval\s*\(", r"\bfloatval\s*\(", r"\(\s*int\s*\)", r"\(\s*float\s*\)",
                   r"\bintdiv\s*\(", r"\bsettype\s*\(", r"\babsint\s*\(",
                   r"array_map\s*\(\s*['\"](?:intval|absint|floatval)['\"]"],
    "java":       [r"Integer\.parseInt", r"Long\.parseLong", r"Double\.parseDouble",
                   r"Integer\.valueOf", r"Long\.valueOf"],
    "go":         [r"strconv\.Atoi", r"strconv\.ParseInt", r"strconv\.ParseFloat"],
    "ruby":       [r"\.to_i\b", r"\.to_f\b", r"\bInteger\s*\(", r"\bFloat\s*\("],
    "c_sharp":    [r"int\.Parse", r"Int32\.Parse", r"Int64\.Parse", r"Convert\.ToInt32",
                   r"long\.Parse"],
    "rust":       [r"\.parse::<", r"\bas\s+i\d", r"\bas\s+u\d"],
    "cpp":        [r"\batoi\s*\(", r"\bstoi\s*\(", r"\bstrtol\s*\("],
    "c":          [r"\batoi\s*\(", r"\bstrtol\s*\(", r"\batol\s*\("],
    "kotlin":     [r"\.toInt\s*\(", r"\.toLong\s*\(", r"\.toDouble\s*\(", r"\.toIntOrNull"],
}


def concat_input_is_cast(source: str, language: str) -> bool:
    """True if EVERY variable concatenated/interpolated into a string in this unit
    is the result of a numeric cast. Such values are integers/floats and cannot
    carry an injection payload, so the concatenation is safe. Conservative: if any
    concatenated variable is not provably a cast, returns False (treat as unsafe)."""
    casts = _CAST_PATTERNS.get(language, [])
    if not casts:
        return False
    code = _strip_doc_and_comments(source, language)
    # Normalise `implode(SEP, $arr)` -> `$arr` so an imploded integer-cast array
    # (e.g. implode(',', array_map('intval', $ids)) used in an IN(...) clause) is
    # evaluated by the cast check on the array variable rather than on `implode`.
    # SEP may be a quoted string that itself contains a comma, hence the alternation.
    code = re.sub(r"""\bimplode\s*\(\s*(?:'[^']*'|"[^"]*"|[^,()'"]*)\s*,\s*(array_map\s*\(\s*['\"](?:intval|absint|floatval)['\"][^()]*\([^()]*\)[^()]*\))\s*\)""",
                  r"\1", code)
    code = re.sub(r"""\bimplode\s*\(\s*(?:'[^']*'|"[^"]*"|[^,()'"]*)\s*,\s*(\$?[A-Za-z_]\w*)\s*\)""",
                  r"\1", code)
    concat_vars = set()
    # "literal" <concat-op> VAR   (+, ., or Rust/format interpolation)
    for m in re.finditer(r'["\'][^"\']*["\']\s*[.+]\s*&?\$?([A-Za-z_]\w*)', code):
        concat_vars.add(m.group(1))
    # VAR <concat-op> "literal"
    for m in re.finditer(r'&?\$?([A-Za-z_]\w*)\s*[.+]\s*["\']', code):
        concat_vars.add(m.group(1))
    # ${var} / #{var} / {var}  interpolation
    for m in re.finditer(r'[$#]\{\s*([A-Za-z_]\w*)', code):
        concat_vars.add(m.group(1))
    for m in re.finditer(r'\{\s*([A-Za-z_]\w*)\s*\}', code):
        concat_vars.add(m.group(1))
    if not concat_vars:
        return False
    for v in concat_vars:
        cast_here = False
        for am in re.finditer(r'\$?' + re.escape(v) + r'\s*(?::?=|:=)\s*([^;\n]+)', code):
            if any(re.search(c, am.group(1)) for c in casts):
                cast_here = True
                break
        if not cast_here:
            return False   # this concatenated var is not a cast -> potentially unsafe
    return True


# framework db-handle names whose `->prop` interpolation is a trusted table /
# column identifier (e.g. {$wpdb->posts}), never attacker input.
_DB_HANDLE_RE = re.compile(r"^(wpdb|db|pdo|conn|connection|mysqli|dbh|link|self|this)$", re.I)
_SAFE_TABLE_PROP_RE = re.compile(
    r"->\s*(comments|posts|users|usermeta|postmeta|options|terms|term\w*|links|"
    r"blogs|signups|prefix|base_prefix|\w*table\w*|table_name)$", re.I)


def _sql_input_vars(source: str, language: str) -> set:
    """Variables concatenated/interpolated specifically INTO a SQL string in this
    unit. Framework table-handle properties ({$wpdb->posts}, $this->prefix) are
    excluded because they are trusted identifiers, not user input."""
    code = _strip_doc_and_comments(source, language)
    # implode(SEP, $arr) -> $arr so an imploded list is judged on the array var
    code = re.sub(r"""\bimplode\s*\(\s*(?:'[^']*'|"[^"]*"|[^,()'"]*)\s*,\s*(\$?[A-Za-z_]\w*)\s*\)""",
                  r"\1", code)
    sql_kw = re.compile(
        r"\bSELECT\b[\s\S]*\bFROM\b|\bINSERT\s+INTO\b|\bUPDATE\b[\s\S]*\bSET\b"
        r"|\bDELETE\s+FROM\b|\bFROM\b[\s\S]*\bWHERE\b|\bWHERE\b[\s\S]*[=<>]", re.IGNORECASE)
    string_literals = re.findall(
        r'`(?:[^`\\]|\\.)*`|(?:f|r|b)?"(?:[^"\\]|\\.)*"|(?:f|r|b)?\'(?:[^\'\\]|\\.)*\'', code)
    sql_strings = [s for s in string_literals if sql_kw.search(s)]
    out = set()
    for lit in sql_strings:
        # interpolated vars inside the SQL literal (skip trusted table handles)
        for name, prop in re.findall(r"\$\{?\s*([A-Za-z_]\w*)((?:\s*->\s*\w+)?)", lit):
            if prop and (_DB_HANDLE_RE.match(name) or _SAFE_TABLE_PROP_RE.search(prop)):
                continue
            out.add(name)
        # concatenation immediately adjacent to this SQL string
        try:
            idx = code.index(lit)
        except ValueError:
            continue
        after = code[idx + len(lit): idx + len(lit) + 80]
        before = code[max(0, idx - 80):idx]
        for m in re.finditer(r"(?:\.|\+)\s*\$?([A-Za-z_]\w*)", after):
            out.add(m.group(1))
        for m in re.finditer(r"\$?([A-Za-z_]\w*)\s*(?:\.|\+)\s*$", before):
            out.add(m.group(1))
    return out


def _var_is_validated(var: str, code: str, _seen=None) -> bool:
    """A SQL-input var is safe if it is integer-cast, validated against a fixed
    allow-list (in_array / switch), escaped/sanitised in place (array_walk +
    escape, esc_sql, $wpdb->_escape), assigned from a value with safe provenance
    (a framework sanitiser / escaping helper / date-time builtin), OR built only
    from other variables that are themselves validated (transitive provenance,
    e.g. $types = "'".implode("','", $post_type)."'" where $post_type was
    escaped). Bounded by a visited set to avoid cycles."""
    if _seen is None:
        _seen = set()
    if var in _seen:
        return False
    _seen.add(var)
    casts = _CAST_PATTERNS.get("php", []) + _CAST_PATTERNS.get("python", [])
    v = re.escape(var)
    # assignment to a cast expression OR a safe-provenance call
    for am in re.finditer(r'\$?' + v + r'\s*(?::?=|:=|\.=)\s*([^;\n]+)', code):
        rhs = am.group(1)
        if any(re.search(c, rhs) for c in casts):
            return True
        if _SAFE_PROVENANCE_RE.search(rhs):
            return True
    # whitelist validation: in_array($var, array(...)) / switch($var)
    if re.search(r"in_array\s*\(\s*\$?" + v + r"\s*,", code):
        return True
    if re.search(r"\bswitch\s*\(\s*\$?" + v + r"\s*\)", code):
        return True
    # escaped in place: array_walk($var, [...escape...]) or sanitiser($var)
    if re.search(r"array_walk\s*\(\s*\$?" + v + r"\s*,[^)]*(escape|sanit)", code, re.IGNORECASE):
        return True
    if re.search(r"(?:sanitize_\w+|esc_sql|esc_like|escape_by_ref|real_escape\w*)\s*\(\s*&?\$?" + v + r"\b",
                 code, re.IGNORECASE):
        return True
    # transitive: built only from other variables that are themselves validated
    for am in re.finditer(r'\$?' + v + r'\s*(?::?=|:=|\.=)\s*([^;\n]+)', code):
        rhs = am.group(1)
        rhs_vars = set(re.findall(r'\$([A-Za-z_]\w*)', rhs)) - {var}
        rhs_vars = {w for w in rhs_vars if not _DB_HANDLE_RE.match(w)}
        if rhs_vars and all(_var_is_validated(w, code, _seen) for w in rhs_vars):
            return True
    return False


# Functions whose return value cannot carry a SQL-injection payload: framework
# input sanitisers, escaping helpers, and date/time/id builtins. A variable
# assigned from one of these is treated as safe SQL input.
_SAFE_PROVENANCE_RE = re.compile(
    r"\b(?:sanitize_\w+|esc_sql|esc_like|escape_by_ref|real_escape\w*|"
    r"wp_parse_id_list|wp_parse_list|absint|intval|floatval|"
    r"gmdate|date|mktime|current_time|time)\s*\("
    r"|->\s*(?:quote|_escape|prepare)\s*\(",
    re.IGNORECASE,
)


def sql_concat_input_is_safe(source: str, language: str) -> bool:
    """True if EVERY variable that flows into a SQL string in this unit is safe
    (integer-cast or allow-list validated). Localised to the SQL-relevant vars so
    a large module-level unit is not penalised for unrelated concatenation, while
    assignments/validations elsewhere in the unit are still honoured."""
    if language not in ("php", "python", "javascript", "typescript"):
        return False
    vars_ = _sql_input_vars(source, language)
    if not vars_:
        return False
    code = _strip_doc_and_comments(source, language)
    return all(_var_is_validated(v, code) for v in vars_)


def numeric_params(params):
    risky = ("amount", "price", "discount", "qty", "quantity", "total",
             "cost", "balance", "credit", "sum", "rate", "fee", "count")
    return [p for p in params if any(k in p.lower() for k in risky)]


def id_params(params):
    """Parameters that look like a direct object identifier the client controls.
    Matches precise id naming (id, user_id, order_id, ...) rather than broad
    substrings like 'object' or 'key' that produce false positives."""
    out = []
    for p in params:
        pl = p.lower().strip("$")
        # exact-ish id naming: 'id', '*_id', 'id_*', 'uid', or '<noun>id'
        if (pl in ("id", "uid", "gid", "pid", "oid")
                or pl.endswith("_id") or pl.endswith("id")
                or pl.startswith("id_")
                or pl in ("user_id", "userid", "account_id", "order_id", "invoice_id",
                          "doc_id", "file_id", "post_id", "comment_id", "object_id",
                          "record_id", "entity_id", "owner_id")):
            # avoid generic words that merely END in 'id' by accident
            if pl in ("valid", "void", "grid", "guid", "android", "rapid", "hybrid",
                      "solid", "fluid", "candid"):
                continue
            out.append(p)
    return out


def has_bound_check(source: str) -> bool:
    # recognise an explicit numeric/range guard OR an input-validation guard that
    # rejects bad values (e.g. `if float(x) <= 0: return (..., 400)`)
    if re.search(r"(<=?\s*\d+|>=?\s*\d+|>\s*0|<\s*0|max\(|min\(|clamp|abs\()", source):
        return True
    if re.search(r"(invalid|400|abort\(4|raise\s+\w*(ValueError|BadRequest))", source, re.IGNORECASE) and \
       re.search(r"(<=?|>=?|==|<|>)\s*\d", source):
        return True
    return False


def has_ownership_check(source: str) -> bool:
    # strip only comments/docstrings (NOT string literals -- ownership checks
    # often compare against string keys like obj["owner"] or session.get("user")).
    s = source
    s = re.sub(r"#.*", "", s)
    s = re.sub(r"//.*", "", s)
    s = re.sub(r'"""(?:.|\n)*?"""', "", s)
    s = re.sub(r"'''(?:.|\n)*?'''", "", s)
    sl = s.lower()
    patterns = [
        r"owner", r"current_user", r"session\.", r"session\[", r"\.user_id",
        r"request\.user", r"authoriz",
        r"current\.id", r"belongs_to", r"\.user\b", r"auth\.user", r"g\.user",
        r"req\.user", r"==\s*session", r"session.*==", r"permission",
        r"can_access", r"is_owner", r"\b403\b", r"forbidden",
        # additional GENUINE guards (raise precision WITHOUT weakening recall --
        # each is a DELIBERATE protective construct, not a loose substring that
        # could also appear in a vulnerable handler):
        r"abort\(\s*40[13]",                        # abort(401/403): explicit auth-fail
        r"\.owns\b", r"owns_", r"_owns\b",          # ownership helpers
        r"check_\w*access", r"verify_\w*owner", r"ensure_\w*owner",
        r"verify_\w*access", r"has_\w*permission", r"\.can\(",
        r"filter_by\([^)]*\b(owner|user|account|tenant|org)",  # query scoped to principal
        r"filter\([^)]*\b(owner|user|account|tenant|org)",
        # an explicit comparison ON a scope/identity field is a deliberate check
        # (a fetch-only IDOR never compares these) -> recall-safe:
        r"(owner_id|user_id|account_id|tenant_id|org_id)\s*(==|!=)",
        r"==\s*(owner_id|user_id|account_id|tenant_id|org_id)",
        r"policy\.", r"\bacl\b", r"permitted", r"scoped_to",
        # Verifying a secret / one-time key / token IS authorization: possessing
        # the correct unguessable key proves the request is legitimate (e.g.
        # password-reset / email-confirmation flows). A fetch-only IDOR has none.
        r"hash_equals", r"compare_digest", r"wp_hasher", r"checkpassword",
        r"check_password", r"wp_check_password", r"confirm_key", r"verify_key",
        r"->\s*check\s*\(", r"verify_\w*token", r"validate_\w*key",
        r"secret_compare", r"timingsafe", r"constant_time",
    ]
    return any(re.search(p, sl) for p in patterns)


# Client-input accessors across frameworks: PHP superglobals, Flask/Django
# request.*, Express req.*, Rails params, generic cookies. Used to require that a
# role token is genuinely the client-controlled key, not just a nearby predicate.
_CLIENT_ACCESSOR = (
    r"(?:\$_(?:GET|POST|REQUEST|COOKIE)"
    r"|request\.(?:form|args|values|json|data|cookies|GET|POST|params|query|body)"
    r"|req\.(?:body|query|params|cookies)"
    r"|\bparams\b|\bcookies?\b)"
)


def reads_client_role(source: str, language: str) -> bool:
    """Detect a role/privilege flag read directly from client input.

    The role token must actually BE the client-controlled key, or the variable
    assigned directly from client input -- not merely co-occur in the same
    statement. This avoids false positives such as
        if ( is_admin() && isset( $_GET['meta-box-loader'] ) )
    where `is_admin()` is a framework predicate (are we on an admin page) and the
    client value `meta-box-loader` is unrelated to any role."""
    code = _strip_doc_and_comments(source, language)
    for tok in ROLE_TOKENS:
        t = re.escape(tok)
        # (a) role token is the KEY read from a client source:
        #     $_POST['role'], request.form['is_admin'], params[:role],
        #     request.args.get('user_type'), cookies['role']
        if re.search(
                _CLIENT_ACCESSOR +
                r"""\s*(?:\[\s*['"]|\.\s*get\s*\(\s*['"]|\[\s*:)\s*[\w.-]*""" + t,
                code, re.IGNORECASE):
            return True
        # (b) attribute access on a request object ending in the role token:
        #     req.body.role, request.user_type
        if re.search(r"\b(?:request|req)\b(?:\.\w+)*\.\s*" + t + r"\b", code, re.IGNORECASE):
            return True
        # (c) a variable whose name contains the role token is assigned DIRECTLY
        #     from a client source in the same statement: $role = $_POST['x']
        if re.search(r"\$?\w*" + t + r"\w*\s*=\s*[^=\n;]*" + _CLIENT_ACCESSOR,
                     code, re.IGNORECASE):
            return True
    return False


# Untrusted-input sources: request data / superglobals / stdin per language. Used
# by the broad regex matchers to avoid firing on internal-only data (framework
# table identifiers, already-sanitised fragments) that no external attacker can
# influence -- a dominant false-positive source on large real-world code bases.
# Cross-function flows (source in a caller) are covered separately by the taint
# engine, which performs its own interprocedural source tracking.
_UNTRUSTED_SOURCE_RE = re.compile(
    r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b"                 # PHP superglobals
    r"|php://input"                                                  # PHP raw body
    r"|HTTP_RAW_POST_DATA"
    r"|\brequest\.(?:args|form|values|json|data|files|cookies|GET|POST|get_json|body|query|params)\b"
    r"|\breq\.(?:query|body|params|headers|cookies|param)\b"         # Express/Node
    r"|\bgetParameter\s*\(|@RequestParam|@PathVariable|@RequestBody" # Java
    r"|\bparams\.(?:require|permit|fetch)|\bparams\[",               # Rails
    re.IGNORECASE,
)


def has_untrusted_source(source: str, language: str) -> bool:
    """True if the unit reads a request / superglobal / user-controlled input
    source directly. Lets matchers require attacker-reachable input before
    flagging, which removes false positives on internal-only data flows."""
    code = _strip_doc_and_comments(source, language)
    return bool(_UNTRUSTED_SOURCE_RE.search(code))


_HTML_LIT_RE = r"['\"][^'\"]*<\s*[a-zA-Z/!][^>]*>"


def xss_output_is_request_tainted(source: str, language: str) -> bool:
    """True only if a value written into HTML actually derives from a request
    source: a superglobal/request accessor concatenated or interpolated into an
    HTML string, or a variable that was assigned from one and then emitted into
    HTML. A value that is a (sanitised) parameter, a stored/internal value, or a
    constant is NOT reflected XSS even if the function reads request data
    elsewhere -- cross-function tainted flows are covered by the taint engine."""
    code = _strip_doc_and_comments(source, language)
    sg = (r"(?:\$_(?:GET|POST|REQUEST|COOKIE)\s*\[|request\.(?:args|form|values|GET|POST|"
          r"params|query|data|cookies)|req\.(?:query|body|params|cookies)|getParameter\s*\()")

    # (1) a request source concatenated/interpolated DIRECTLY into HTML
    if re.search(_HTML_LIT_RE + r"[^'\"]*['\"]\s*[.+]\s*" + sg, code) or \
       re.search(sg + r"[^\n;]*?[.+]\s*" + _HTML_LIT_RE, code) or \
       re.search(r"(?:`|f['\"])[^`'\"]*<[^`'\"]*(?:\$\{[^}]*" + sg + r"|\{[^}]*"
                 + sg.replace(r"\$_", "_") + r")", code):
        return True

    # (2) a variable assigned from a request source, then emitted into HTML
    tainted = set(re.findall(r"\$?([A-Za-z_]\w*)\s*=\s*[^=\n;]*" + sg, code))
    for v in tainted:
        vb = re.escape(v)
        if re.search(_HTML_LIT_RE + r"[^'\"]*['\"]\s*[.+]\s*\$?" + vb + r"\b", code) or \
           re.search(r"\$?" + vb + r"\b\s*[.+]\s*" + _HTML_LIT_RE, code) or \
           re.search(r"(?:`|f['\"])[^`'\"]*<[^`'\"]*[{$]\{?\s*" + vb + r"\b", code):
            return True
    return False


def sql_concat_vars(source: str, language: str) -> set:
    """Return the set of variable names concatenated or interpolated into a
    string literal in this unit. Used to tell whether a function PARAMETER (which
    is externally supplied, hence potentially attacker-controlled) flows into a
    built SQL string, so a standalone vulnerable helper is still flagged while
    internal-only concatenation (framework identifiers, sanitised fragments) is
    not."""
    code = _strip_doc_and_comments(source, language)
    out = set()
    for m in re.finditer(r'["\'][^"\']*["\']\s*[.+]\s*&?\$?([A-Za-z_]\w*)', code):
        out.add(m.group(1))
    for m in re.finditer(r'&?\$?([A-Za-z_]\w*)\s*[.+]\s*["\']', code):
        out.add(m.group(1))
    for m in re.finditer(r'[$#]\{\s*([A-Za-z_]\w*)', code):       # ${var} / #{var}
        out.add(m.group(1))
    for m in re.finditer(r'\{\s*([A-Za-z_]\w*)\s*\}', code):       # {var}
        out.add(m.group(1))
    # plain PHP/shell interpolation inside double quotes: "... $var ..."
    for m in re.finditer(r'"[^"]*?\$([A-Za-z_]\w*)[^"]*"', code):
        out.add(m.group(1))
    return out


_SQL_KW_RE = re.compile(
    r"\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|REPLACE\s+INTO|UNION\s+SELECT|"
    r"\bFROM\b|\bWHERE\b|\bVALUES\b|\bJOIN\b|\bSET\b)\b", re.IGNORECASE)


def param_flows_into_sql(source: str, language: str, params) -> bool:
    """True if a function parameter is concatenated/interpolated into a string
    that ACTUALLY contains SQL keywords (so a standalone vulnerable helper like
    `q("SELECT ... " . $name)` is flagged), while a parameter that only flows into
    an unrelated string (a cache key, a log line) is not. Precise enough to keep
    Zero-FP on framework code where the dangerous-looking param feeds a sanitised
    fragment rather than the query itself."""
    if not params:
        return False
    pnames = {str(p).lstrip("$&*").strip() for p in params if p}
    pnames = {p for p in pnames if p}
    if not pnames:
        return False
    code = _strip_doc_and_comments(source, language)
    # examine only the text window around each SQL keyword occurrence
    for m in _SQL_KW_RE.finditer(code):
        window = code[max(0, m.start() - 160): m.end() + 160]
        if pnames & sql_concat_vars(window, language):
            return True
    return False
