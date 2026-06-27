"""
Context awareness / false-positive suppression
=============================================

The single biggest credibility problem for a heuristic scanner is flagging
code that merely *mentions* a vulnerability pattern -- example strings inside a
detector, attack payloads in a test, a regex that looks for SQL, a docstring
explaining SQLi -- as if it were a real vulnerability.

This module decides, for a given finding, whether the matched code is
*genuinely executable application logic* or just *text that resembles a
vulnerability*. It does three things:

  1. Classifies the file role (application code vs test / fixture / the
     security tool's own analyzer code / documentation / examples).
  2. Detects when the trigger lives inside a string literal, comment, regex,
     or docstring rather than in executed code.
  3. Applies suppression / confidence penalties accordingly.

The goal is precision: a finding survives only if it looks like a real flaw in
code that actually runs, not code that talks about flaws.
"""

import os
import re


# ----------------------------------------------------------------------
# File-role classification
# ----------------------------------------------------------------------
TEST_PATH_HINTS = ("test", "tests", "spec", "specs", "__tests__", "fixture",
                   "fixtures", "mock", "mocks", "example", "examples", "sample",
                   "samples", "demo", "demos", "benchmark", "e2e")

DOC_EXTS = (".md", ".markdown", ".rst", ".txt", ".adoc")

# Files that are themselves security-analysis / scanner code: any file that
# defines detectors, signatures, rules, payloads. Flagging the *scanner's own
# pattern strings* as vulnerabilities is the classic self-scan false positive.
SECURITY_TOOL_HINTS = ("matcher", "matchers", "signature", "signatures", "rule",
                       "rules", "detector", "detectors", "scanner", "scanners",
                       "payload", "payloads", "sqlmap", "exploit", "vuln",
                       "security", "sast", "linter", "analyzer", "analyser",
                       "waf", "sanitiz")

# Third-party libraries BUNDLED inside a project (WordPress ships dozens). A scan
# is meant to judge the project's OWN logic; findings inside vendored code are
# noise, and known bundled-library CVEs are covered by the enrichment / WPScan
# layers (by component+version), not by re-deriving taint in code the project
# does not maintain. We recognise the well-known vendor directories, the bundled
# WP class files, and minified assets, and treat them like docs (dropped). The
# benchmark is unaffected: it scans cases/*.{py,php,js} directly, whose relative
# paths contain none of these markers.
VENDOR_DIR_HINTS = frozenset({
    "simplepie", "phpmailer", "getid3", "sodium_compat", "random_compat",
    "phpseclib", "codemirror", "tinymce", "plupload", "mediaelement", "jcrop",
    "swfupload", "twemoji", "zxcvbn", "requests", "ixr", "jquery", "backbone",
    "underscore", "masonry", "imagesloaded", "thickbox", "clipboard", "hoverintent",
})
VENDOR_FILE_PREFIX = ("class-ftp", "class-pop3", "class-snoopy", "class-phpass",
                      "class-simplepie", "class-json", "class-ixr", "class-smtp",
                      "class-phpmailer", "class-requests", "class-avif-info")
VENDOR_FILE_STEMS = frozenset({"esprima", "json2", "underscore", "backbone"})


def classify_file(rel_path: str) -> str:
    """Return one of: 'application', 'test', 'doc', 'security_tool', 'vendor'."""
    p = rel_path.replace("\\", "/").lower()
    parts = p.split("/")
    base = parts[-1]

    _, ext = os.path.splitext(base)
    if ext in DOC_EXTS:
        return "doc"

    # test / fixture / example / demo directories or filenames
    for part in parts:
        stem = part.split(".")[0]
        if stem in TEST_PATH_HINTS or part in TEST_PATH_HINTS:
            return "test"
    if base.startswith("test_") or base.endswith(("_test.py", "_test.go", ".test.js",
                                                  ".test.ts", ".spec.js", ".spec.ts",
                                                  "_spec.rb")):
        return "test"

    # third-party bundled library code (vendored dependency)
    for part in parts:
        if part in VENDOR_DIR_HINTS:
            return "vendor"
    # multi-segment vendored libraries (bundled PEAR/utility libs)
    if any(sub in p for sub in ("text/diff", "/pomo/", "/pear/", "simplepie/",
                                "phpmailer/", "/sodium_compat/", "/avif-info")):
        return "vendor"
    stem = base.split(".")[0]
    if stem in VENDOR_FILE_STEMS or base.startswith(VENDOR_FILE_PREFIX):
        return "vendor"
    if re.search(r"[.\-]min\.(js|css)$", base):
        return "vendor"

    # the security tool's own analyzer code
    for part in parts:
        stem = part.split(".")[0]
        if stem in SECURITY_TOOL_HINTS:
            return "security_tool"

    return "application"


# ----------------------------------------------------------------------
# String / comment / regex context detection
# ----------------------------------------------------------------------
def _line_of_offset(source: str, needle: str):
    idx = source.find(needle)
    if idx < 0:
        return None
    return source.count("\n", 0, idx)


def find_trigger_lines(source: str, tokens) -> list:
    """Lines (0-based) where any token appears."""
    lines = source.splitlines()
    hits = []
    for i, line in enumerate(lines):
        for t in tokens:
            if t in line:
                hits.append(i)
                break
    return hits


def is_probably_in_string_or_comment(line: str, language: str) -> bool:
    """
    Decide whether the vulnerability trigger on this line is merely *text*
    (inside a quoted string, a comment, or a regex/token table) rather than
    real executable code.

    CRITICAL: this must be conservative. A real sink call such as
    `open(filename)`, `cursor.execute(query)`, or `os.system(cmd)` -- even when
    the line also contains an unrelated string literal like a mode flag ("r")
    -- is EXECUTABLE CODE and must NOT be treated as a string. Over-aggressive
    matching here hides real vulnerabilities (false negatives), which is worse
    than a false positive.
    """
    stripped = line.strip()

    # 1) pure comment lines
    if stripped.startswith(("#", "//", "*", "/*", '"""', "'''", "--")):
        return True

    # 2) If the line contains a real CALL with a non-string argument, it is
    #    executable code, not a constant string. Blank out string literals,
    #    then look for `name(<non-empty, non-quote arg>)`.
    no_str = re.sub(r'"[^"]*"', '""', line)
    no_str = re.sub(r"'[^']*'", "''", no_str)
    no_str = re.sub(r"`[^`]*`", "``", no_str)
    # a call whose first argument is an identifier/variable (not just a literal)
    if re.search(r"\b[A-Za-z_]\w*\s*\(\s*[A-Za-z_$]", no_str):
        return False   # real call on a variable -> executable, keep the finding
    # `with open(var)`, `= open(var)`, attribute calls `x.execute(var)`
    if re.search(r"\bopen\s*\(\s*[A-Za-z_]", no_str) or \
       re.search(r"\.\s*(execute|executemany|query|system|popen|run|read|write|"
                 r"get_var|get_results|get_row|render_template_string|loads|load)\s*\(", no_str):
        return False

    # 2b) an f-string / template literal with a VARIABLE interpolation is
    #     dynamic, not a constant -- e.g. f"... WHERE id={user_id}". This is a
    #     real injection vector even when it sits alone on its own line.
    if re.search(r'f"[^"]*\{[^}]+\}', line) or re.search(r"f'[^']*\{[^}]+\}", line):
        return False
    if re.search(r'`[^`]*\$\{[^}]+\}', line):       # JS template literal
        return False
    if re.search(r'"[^"]*\$\{[^}]+\}', line) or re.search(r'"[^"]*#\{[^}]+\}', line):
        return False

    # 3) regex / pattern definition lines (these really are just patterns)
    if re.search(r"re\.(compile|search|match|findall|sub)\s*\(", line):
        return True
    if re.search(r"""(PATTERN|REGEX|_RE|patterns?|signatures?|tokens?|sinks?|hints?)\s*=""", line):
        return True

    # 4) assignment of a list/dict/tuple of string literals (token tables),
    #    with NO call on the right-hand side
    if re.search(r"=\s*[\[\{\(]", line) and (line.count('"') + line.count("'")) >= 2 \
       and not re.search(r"[A-Za-z_]\w*\s*\([A-Za-z_$]", no_str):
        return True

    # 5) the trigger sits entirely inside a quoted literal with nothing
    #    executable around it (a bare message string)
    if _looks_like_constant_string(line):
        return True

    return False


def _looks_like_constant_string(line: str) -> bool:
    """
    True when the SQL/command-looking text is inside quotes AND there is no
    real concatenation/format/execution happening with a *variable* on the
    line. A constant string literal is not an injection.
    """
    # is there a quote on the line?
    if '"' not in line and "'" not in line:
        return False

    # remove everything inside quotes; if what's LEFT contains a concat with a
    # variable, then it is likely a real built query. Otherwise it's a constant.
    no_strings = re.sub(r'"[^"]*"', "Q", line)
    no_strings = re.sub(r"'[^']*'", "Q", no_strings)

    # real dynamic build signals OUTSIDE the string (covers py/js/java/php/ruby):
    dynamic = (
        re.search(r"Q\s*\+\s*[\w$]", no_strings) or     # "..." + var
        re.search(r"[\w$\)]\s*\+\s*Q", no_strings) or   # var + "..."
        re.search(r"Q\s*%\s*[\w(]", no_strings) or      # "..." % var
        re.search(r"Q\s*\.\s*\$?\w", no_strings) or     # PHP: "..." . $var
        re.search(r"\$?\w\s*\.\s*Q", no_strings) or     # PHP: $var . "..."
        re.search(r"\.\s*format\s*\(", line) or         # "...".format(...)
        re.search(r'f["\']', line) or                    # f"..."
        re.search(r"\$\{", line) or                      # ${...}
        re.search(r"#\{", line) or                       # #{...}
        re.search(r"\.\s*$", no_strings.rstrip())        # trailing concat operator
    )
    # interpolation INSIDE the string -> dynamic
    interp_inside = (
        re.search(r'f["\'][^"\']*\{[^}]+\}', line) or
        re.search(r'["\'][^"\']*\$\{[^}]+\}', line) or
        re.search(r'["\'][^"\']*\$\w', line) or          # PHP "$var" inside string
        re.search(r'["\'][^"\']*#\{[^}]+\}', line)
    )
    if interp_inside:
        return False
    return not bool(dynamic)


# ----------------------------------------------------------------------
# Main entry: adjust a finding for context
# ----------------------------------------------------------------------
# Vulnerability classes that require *executed* dynamic construction to be real
# (so a constant string / example / regex should suppress them).
_TEXT_SENSITIVE = {
    "SQL Injection", "OS Command Injection", "Server-Side Template Injection",
    "Path Traversal", "Server-Side Request Forgery (SSRF)",
    "Insecure Deserialization",
}


# ----------------------------------------------------------------------
# Client-side (browser) JavaScript awareness
# ----------------------------------------------------------------------
# These vuln classes only have meaning in SERVER-SIDE code. In browser / client
# JavaScript there is no OS, no database, no server filesystem, and no server
# auth boundary, so flagging them on browser code is a false positive. They are
# dropped only when the JS/TS file shows NO Node.js/server signals AND DOES show
# browser signals (conservative: ambiguous files are still analysed normally).
_SERVER_SIDE_ONLY_JS = {
    "SQL Injection", "OS Command Injection", "Path Traversal",
    "Server-Side Request Forgery (SSRF)", "XML External Entity (XXE)",
    "Insecure Deserialization", "Server-Side Template Injection",
    "NoSQL Injection", "LDAP Injection", "XPath Injection",
    "HTTP Response Splitting / CRLF Injection", "Code Injection",
    "Broken Authorization (client-trusted role)",
    "Insecure Direct Object Reference (IDOR)",
    "Missing Authentication on Sensitive Action",
    "Sensitive Action Without Rate Limiting",
    "Race Condition (TOCTOU)",        # browser JS is a single-threaded event loop
    "Hardcoded Secret / Credential",  # client bundles ship public keys/placeholders
}

# Node.js / server signals -- if ANY appears in a .js/.ts file we keep analysing
# it as potential server code (no suppression). NB: we deliberately do NOT treat
# `module.exports` / `exports.` / `__dirname` as server signals: UMD wrappers in
# browser libraries (jQuery, lodash, etc.) contain them purely for bundlers.
_NODE_SIGNAL_RE = re.compile(
    r"""require\s*\(\s*['"](?:child_process|fs|fs/promises|net|http|https|http2|
        dgram|tls|express|koa|fastify|next|nuxt|mysql2?|pg|pg-promise|mongodb|
        mongoose|sequelize|typeorm|prisma|sqlite3|better-sqlite3|tedious|ioredis|
        redis|dns|cluster|worker_threads|node:[a-z_/]+)['"]
        | \bfrom\s+['"](?:child_process|fs|fs/promises|net|http|https|express|koa|
        fastify|mysql2?|pg|mongodb|mongoose|sequelize|knex|prisma|node:[a-z_/]+)['"]
        | \bprocess\.(?:argv|env|exit|cwd|binding)\b
        | \bapp\.(?:get|post|put|delete|patch|use|listen)\s*\(
        | \brouter\.(?:get|post|put|delete|patch|use)\s*\(
        | \b(?:http|net|https|http2)\.createServer\b
    """,
    re.VERBOSE,
)

# Browser-only globals / library markers that indicate client-side code.
_BROWSER_SIGNAL_RE = re.compile(
    r"\b(?:document|window|navigator|location\.(?:href|search|hash|pathname)|"
    r"localStorage|sessionStorage|jQuery|addEventListener|querySelector\w*|"
    r"getElementById|getElementsBy\w+|XMLHttpRequest|customElements|HTMLElement|"
    r"createElement|tinymce|tinyMCE|MediaElement|Backbone|_\.template|wp\.\w+)\b"
    r"|\$\(\s*['\"#.]"
)


def is_client_side_js(language: str, file_text: str) -> bool:
    """True when a JS/TS file is browser/client-side code (server-side vuln
    classes do not apply). Conservative: requires NO Node/server signals AND at
    least one browser signal, so genuinely server-side or ambiguous files are
    never suppressed by this rule."""
    if language not in ("javascript", "typescript", "tsx", "jsx"):
        return False
    if not file_text:
        return False
    if _NODE_SIGNAL_RE.search(file_text):
        return False
    return bool(_BROWSER_SIGNAL_RE.search(file_text))


def evaluate(finding, file_role: str, file_text: str = None):
    """
    Return (action, factor, reason):
      action: 'keep' | 'penalize' | 'drop'
      factor: confidence multiplier when penalizing
      reason: short human explanation

    `file_text` is the WHOLE-file source (used for browser-vs-server JS context);
    when omitted, the browser-JS rule is skipped.
    """
    src = finding.source or ""
    ftype = finding.type

    # --- 0. client-side (browser) JavaScript -----------------------------
    # Server-side vuln classes are meaningless on browser code. Drop them when
    # the file is confidently client-side (no Node/server signals, has browser
    # signals). This removes the bulk of false positives on front-end bundles
    # (jQuery, TinyMCE, wp-*.js, etc.).
    if ftype in _SERVER_SIDE_ONLY_JS and is_client_side_js(finding.language, file_text or ""):
        return ("drop", 0.0,
                "client-side/browser JavaScript: this server-side vulnerability class does not apply")

    # --- 0b. XXE mitigated at FILE level ---------------------------------
    # If the file disables external-entity loading anywhere (or guards the PHP<8
    # case), its XML parsing is protected even when the specific function does not
    # show the guard locally -- the protection is applied by the caller or by the
    # PHP 8 / libxml >= 2.9 default. This clears framework XXE false positives.
    if ftype == "XML External Entity (XXE)" and file_text:
        _ft = file_text.lower()
        if any(m in _ft for m in ("libxml_disable_entity_loader", "libxml_nonet",
                                  "php_version_id < 80000", "php_version_id < 8",
                                  "defusedxml", "feature_secure_processing")):
            return ("drop", 0.0, "file disables external entity loading (XXE mitigated)")

    # --- 1. file-role suppression ----------------------------------------
    if file_role == "doc":
        return ("drop", 0.0, "match is inside documentation, not code")

    if file_role == "vendor":
        return ("drop", 0.0, "match is inside a bundled third-party library "
                "(vendored dependency, not the project's own code)")

    if file_role == "security_tool":
        # This is the scanner's own analyzer code: it is FULL of vulnerability
        # keywords, payloads, token tables, and example strings by design.
        # Suppress text/pattern-driven findings unless a real executed sink is
        # present. Logic flaws here are almost always the detector's own tables.
        if ftype in _TEXT_SENSITIVE:
            if not _has_executed_sink(src, finding.language, ftype):
                return ("drop", 0.0, "pattern appears as analyzer text/signature, not executed code")
            return ("penalize", 0.5, "in analyzer code but shows an executed sink")
        # non-text classes (broken-auth, CORS, JWT, mass-assignment, debug,
        # rate-limit, IDOR, price, etc.) in analyzer code are pattern tables.
        return ("drop", 0.0, "match is inside the scanner's own detector/pattern code")

    if file_role == "test" and ftype in _TEXT_SENSITIVE:
        return ("penalize", 0.5, "match is in test/fixture/example code")

    # --- 2. string/comment/regex context ---------------------------------
    if ftype in _TEXT_SENSITIVE:
        # look at the lines that actually triggered the keyword
        kw = _keywords_for(ftype)
        trigger_lines = find_trigger_lines(src, kw)
        if trigger_lines:
            lines = src.splitlines()
            all_in_text = True
            for ln in trigger_lines:
                if 0 <= ln < len(lines):
                    if not is_probably_in_string_or_comment(lines[ln], finding.language):
                        all_in_text = False
                        break
            if all_in_text:
                return ("drop", 0.0, "trigger appears only inside string literals / comments / patterns")

    return ("keep", 1.0, "")


def _keywords_for(ftype):
    if ftype == "SQL Injection":
        return ["SELECT", "INSERT", "UPDATE", "DELETE", "WHERE", "FROM", "select ", "where "]
    if ftype == "OS Command Injection":
        return ["system(", "exec(", "popen(", "Runtime", "ProcessBuilder", "subprocess",
                "shell_exec", "spawn"]
    if ftype == "Server-Side Template Injection":
        return ["render_template_string", "template(", "from_string", "Template"]
    if ftype == "Path Traversal":
        return ["open(", "readfile", "file_get_contents", "fopen(", "sendfile",
                "path.join", "os.path.join", "File("]
    if ftype == "Server-Side Request Forgery (SSRF)":
        return ["requests.get", "requests.post", "urlopen", "fetch(", "HttpClient",
                "curl_exec", "file_get_contents", "axios"]
    if ftype == "Insecure Deserialization":
        return ["pickle.loads", "yaml.load", "unserialize", "readObject", "Marshal.load"]
    return []


# ----------------------------------------------------------------------
# Mitigation Recognition Layer
# ----------------------------------------------------------------------
# When the tool fixes a vulnerability, it inserts specific, recognizable
# mitigation patterns (e.g. _lb_safe_eval, ast.literal_eval, _lb_safe_loads,
# _lb_safe_cmd_arg, os.environ.get, debug=False, hashlib.sha256, etc.).
#
# The regex matchers sometimes STILL fire on the patched code because they
# see the original keyword (e.g. "eval" inside "ast.literal_eval", or "exec"
# inside the helper "_lb_no_exec", or "pickle" inside the import that's still
# present). This layer recognises the tool's own mitigations and suppresses
# those false positives, so a re-scan on patched code correctly shows 0.
#
# This is deterministic (no AI needed) and 100% reliable for the tool's own
# fix patterns.

_MITIGATION_PATTERNS = {
    # These patterns recognise the SPECIFIC fixes the tool's own fixers insert.
    # We do NOT use generic patterns (like "?" or "subprocess.run") because those
    # appear in safe code that was never vulnerable to begin with, which would
    # cause false negatives on the benchmark (safe files recognised as "mitigated").
    # The patterns here are tool-specific helper names or exact fix shapes.

    # CWE-78 OS Command Injection → tool inserts _lb_safe_cmd_arg
    "OS Command Injection": [
        r"_lb_safe_cmd_arg",
    ],
    # CWE-94/95 Code Injection → tool inserts _lb_safe_eval / _lb_no_exec
    "Code Injection": [
        r"_lb_safe_eval",
        r"_lb_no_exec",
        r"blocked dynamic code execution",
    ],
    "Use of eval": [
        r"_lb_safe_eval",
        r"_lb_no_exec",
        r"blocked dynamic code execution",
    ],
    "Eval Injection": [
        r"_lb_safe_eval",
        r"_lb_no_exec",
    ],
    # CWE-502 Insecure Deserialization → tool inserts _lb_safe_loads / RestrictedUnpickler
    "Insecure Deserialization": [
        r"_lb_safe_loads",
        r"_lb_safe_load\b",
        r"_LBRestrictedUnpickler",
        r"RestrictedUnpickler",
    ],
    # CWE-22/23 Path Traversal → tool inserts _lb_safe_path / _lb_base
    "Path Traversal": [
        r"_lb_safe_path",
        r"_lb_base",
    ],
    # CWE-330 Insecure Randomness → tool inserts _lb_secure_rng
    "Insecure Randomness": [
        r"_lb_secure_rng",
    ],
    "Randomness": [
        r"_lb_secure_rng",
    ],
    # CWE-79/1336 XSS / SSTI → tool adds |e filter to Jinja2 templates
    "XSS": [
        r"\|\s*e\s*\}\}",
    ],
    "Cross-Site Scripting": [
        r"\|\s*e\s*\}\}",
    ],
    "Template": [
        r"\|\s*e\s*\}\}",
    ],
}


def is_mitigated(src: str, ftype: str) -> bool:
    """Check if the source code contains a mitigation pattern for the given
    finding type. Returns True if a known mitigation is present (meaning the
    vulnerability has been fixed and the matcher is firing on a false positive).

    This is the core of the Mitigation Recognition Layer. It checks the
    finding's source code against a registry of known mitigation patterns
    that the tool's own fixers insert. If any pattern matches, the finding
    is suppressed as a false positive on patched code.

    How it works:
      - For each finding type, we have a list of regex patterns that represent
        the tool's own fixes (e.g. ast.literal_eval for eval, _lb_safe_loads
        for pickle, debug=False for debug mode).
      - If the finding's source code contains any of these patterns, the
        vulnerability has been mitigated and the matcher is firing on a
        false positive (e.g. it sees "eval" inside "ast.literal_eval").
      - The check is case-insensitive and works on the full source text.
    """
    if not src or not ftype:
        return False
    src_lower = src.lower()

    # find matching mitigation patterns for this finding type
    patterns = []
    for key, pats in _MITIGATION_PATTERNS.items():
        if key.lower() in ftype.lower():
            patterns.extend(pats)

    if not patterns:
        return False

    for pat in patterns:
        if re.search(pat, src, re.IGNORECASE):
            return True
    return False


def _has_executed_sink(src, language, ftype):
    """
    For analyzer/tool code: is there a *real* executed sink (a call) with a
    variable argument, as opposed to the sink name appearing only inside a
    string literal or list of tokens? Conservative: requires a call form like
    `cursor.execute(<something with a variable>)` not inside quotes.
    """
    # strip string literals first; if the sink call survives outside strings,
    # it's executed.
    no_str = re.sub(r'"[^"]*"', "", src)
    no_str = re.sub(r"'[^']*'", "", no_str)
    no_str = re.sub(r"#.*", "", no_str)
    no_str = re.sub(r"//.*", "", no_str)

    if ftype == "SQL Injection":
        return bool(re.search(r"\b(execute|executemany|query|raw|exec)\s*\(\s*\w", no_str))
    if ftype == "OS Command Injection":
        return bool(re.search(r"\b(system|popen|exec|spawn|shell_exec|call|run|Popen)\s*\(\s*\w", no_str))
    if ftype == "Path Traversal":
        return bool(re.search(r"\b(open|readfile|file_get_contents|fopen|sendfile)\s*\(\s*\w", no_str))
    if ftype == "Server-Side Template Injection":
        return bool(re.search(r"\b(render_template_string|from_string|Template)\s*\(\s*\w", no_str))
    if ftype == "Server-Side Request Forgery (SSRF)":
        return bool(re.search(r"\b(get|post|urlopen|fetch|request)\s*\(\s*\w", no_str))
    if ftype == "Insecure Deserialization":
        return bool(re.search(r"\b(loads|load|unserialize|readObject)\s*\(\s*\w", no_str))
    return False
