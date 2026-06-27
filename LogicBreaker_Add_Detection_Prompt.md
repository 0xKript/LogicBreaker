# ADD DETECTION — 6 missed vulnerability types (each ISOLATED, nothing else changed)

> These gaps were found by reading the ACTUAL code and running the tool. Exact
> file/class locations are given. **You must change ONLY what each item names.**
> Do NOT touch the taint engine's flow logic, the wise verdict, the LLM layers,
> other matchers, the CLI, or anything not explicitly listed below. Every fix is
> isolated to ONE matcher (or ONE source list), so it cannot affect existing
> detection. Benchmark-gated: run the benchmark after EVERY change — it must stay
> **100% / 100% / 0 FP** on all 216 cases.

---

## 0) Ground rules (read first — non-negotiable)

- **Scope lock:** the ONLY files you may edit are `matchers/extended.py`,
  `matchers/builtin.py` (only if a matcher is registered there),
  `core/taint_engine.py` (ONLY the source list for item 4), and the benchmark
  `cases/` folder + manifest. Do **not** modify the engine's flow algorithm, the
  verdict, the orchestrator, the LLM code, the CLI, or any other matcher's logic.
- **Isolation:** each matcher is independent — adding a pattern to one matcher
  must not alter any other matcher. Confirm this by keeping the benchmark green.
- **Regression discipline (per item):** after each item, (1) add ONE matched safe
  look-alike to `cases/safe/` proving no new false positive, plus the vuln case to
  `cases/vulnerable/` proving the new catch; (2) regenerate the manifest
  (`python benchmark/build_manifest.py`); (3) run `benchmark/run_benchmark_v2.py`
  → must be 100/100/0; (4) STOP and report what changed + the numbers + confirm
  the new vuln fires and its safe look-alike does NOT.
- Use the project venv interpreter (e.g. `~/lbenv/bin/python`); bare `python` may
  be a Windows stub that runs nothing.
- No API keys anywhere; this work is engine/matcher-only and needs no LLM.

---

## 1) Reflected XSS — add printf-style `%` formatting

**File/class:** `matchers/extended.py` → `ReflectedXSSMatcher` (the `xss` regex).
**Why missed:** it matches `"html" + var` / `var + "html"` (concat) and f-strings /
template literals, but NOT percent-formatting: `return "<h1>Hello %s</h1>" % x`.
**Fix:** add a 4th alternative to the `xss` regex that matches an emit
(`return|echo|print|res.send|...`) of an HTML-tag string literal followed by the
`%` operator and a variable — i.e. `emit ... html_literal ... % ... $?var`. Keep
ALL existing exclusions (escape/markupsafe/htmlspecialchars/JSON/render_template
etc.) and keep the `S.xss_output_is_request_tainted(...)` check so escaped or
non-request output still passes.
**Vuln (must fire):** `return "<h1>Hello %s</h1>" % request.args.get("name","")`
**Safe (must NOT fire):** `return "<h1>%s</h1>" % markupsafe.escape(request.args.get("name",""))`

---

## 2) Insecure Randomness — also check the FUNCTION NAME

**File/class:** `matchers/extended.py` → `InsecureRandomnessMatcher`.
**Why missed:** it requires a security keyword (`_SEC`) within ~50 chars of the
`random.*` call, so `def otp(): return random.randint(...)` is missed — the keyword
`otp` is in the function NAME, not near the call.
**Fix:** ALSO treat the call as security-context when the unit's
qualname/function name itself matches a security term (otp, token, password,
passwd, nonce, salt, secret, csrf, reset_code, reset_token, api_key, session_id,
auth_code, verification_code). Keep the `secrets.` / `SystemRandom` exclusion
(those remain safe).
**Vuln (must fire):** `def otp(): return str(random.randint(100000,999999))`
**Safe (must NOT fire):** `def otp(): return str(secrets.randbelow(900000)+100000)`

---

## 3) Insecure Temp File — NEW matcher

**File:** `matchers/extended.py` → add a new `InsecureTempFileMatcher`.
**Why missed:** no matcher exists for it.
**Fix:** new matcher, `id="insecure-temp-file"`, name "Insecure Temporary File",
`cwe="CWE-377"`, severity MEDIUM. Flag `tempfile.mktemp(` (race-prone, deprecated)
and the bare `mktemp(` call. Do **not** flag the safe APIs:
`tempfile.mkstemp`, `tempfile.NamedTemporaryFile`, `tempfile.TemporaryFile`,
`tempfile.mkdtemp`, `tempfile.TemporaryDirectory`. Register the matcher exactly
where the other extended matchers are registered (same list/loader) — do not
change the loader logic, just add the entry.
**Vuln (must fire):** `def t(): return tempfile.mktemp()`
**Safe (must NOT fire):** `def t(): fd,p = tempfile.mkstemp(); return p`

---

## 4) Unsafe File Upload (path traversal via filename) — add ONE source

**File:** `core/taint_engine.py` → the SOURCE list ONLY (do NOT touch flow logic).
**Why missed:** `request.files` is already a source, but the attacker-controlled
`.filename` attribute is not recognized, so
`f.save("uploads/" + f.filename)` (path traversal, CWE-22) is missed.
**Fix:** add `.filename` as a tainted source feeding the Path Traversal class
(a `request.files[...].filename` / `werkzeug` upload `.filename` flowing into a
file path or `.save(...)`). Recognize `secure_filename(` (werkzeug) as the
neutralizing sanitizer for this source. This is a **source-list addition only** —
do not modify the taint propagation algorithm.
**Vuln (must fire):** `f = request.files["file"]; f.save("uploads/" + f.filename)`
**Safe (must NOT fire):** `f = request.files["file"]; f.save("uploads/" + secure_filename(f.filename))`
After this item, ALSO re-scan the bundled WordPress directory and confirm its
finding count did not increase (no new FP), in addition to the benchmark.

---

## 5) Missing Authorization / IDOR — DO NOT CHANGE (intentional)

A sample like `def user(): uid = request.args.get("id"); return f"Profile {uid}"`
only echoes the id into a string — there is NO real object/DB access, so it is
**not** a genuine IDOR, and the matcher correctly stays silent. **Leave it as is.**
Forcing a detection here would create false positives on virtually every handler
that reads an `id`. This is correct restraint — do not add anything for it.

---

## 6) Weak Cryptography — strengthen (coverage + two tiers)

**File/class:** `matchers/extended.py` → `WeakCryptoMatcher`.
**Why weak today:** (i) several weak-primitive forms are missing from `WEAK_CALLS`;
(ii) the matcher requires a security keyword (`SEC_WORDS`) near EVERY weak call —
but some primitives are broken in ALL contexts, so requiring a nearby keyword makes
them slip through (DES and RC4 were missed for this reason).

**Fix (a) — add missing weak-primitive CALL patterns to `WEAK_CALLS`:**
- `hashlib.new("md5"/"sha1"/"md4"/"sha")` — algorithm passed as a string argument.
- RC4 / ARC4 — `ARC4.new(`, `Crypto.Cipher.ARC4`.
- ECB mode — `MODE_ECB`, `AES.MODE_ECB`, the literal `"ECB"`.
- MD4 / MD2.

**Fix (b) — split into TWO tiers:**
- **ALWAYS-BROKEN** (DES, 3DES/TripleDES, RC4/ARC4, ECB mode, MD4, MD2): flag
  **UNCONDITIONALLY** — these have NO legitimate use, so do NOT require a `SEC_WORD`
  nearby. (This is exactly why DES/RC4 were missed.)
- **CONTEXT-GATED** (MD5, SHA1): KEEP the existing `SEC_WORDS` requirement AND the
  `BENIGN_HINTS` exclusion — md5/sha1 are legitimately used for cache keys / etags /
  checksums, so flagging them unconditionally would create false positives
  (e.g. on WordPress core).

**Vuln (must fire):**
- `DES.new(k, DES.MODE_ECB).encrypt(d)` (no security word) — always-broken tier.
- `hashlib.new("md5", password)`
- `ARC4.new(key).encrypt(d)`
**Safe (must NOT fire):**
- `hashlib.md5(filename).hexdigest()` used as a CACHE KEY (a `BENIGN_HINTS` word
  like `cache`/`etag`/`filename` is present).
- `hashlib.sha256(pw)` / bcrypt / argon2.
After this item, re-scan the bundled WordPress directory and confirm its finding
count did NOT increase (the always-broken tier must not add WordPress FPs), plus
the benchmark stays 100/100/0.

---

## 7) Final full test (do this LAST, after all of 1–4 and 6 are done)

Create a single test file containing ALL of these vulnerabilities and scan it
ENGINE-ONLY (default mode, no LLM), then show me a table of every finding
(severity / CWE / type / line). Confirm that EACH of the following is detected,
and that the deliberately-safe variants are NOT flagged:

Must be detected:
1. SQL Injection (CWE-89)
2. OS Command Injection (CWE-78)
3. Path Traversal (CWE-22)
4. Insecure Deserialization (CWE-502)
5. Reflected XSS via `%` formatting (CWE-79)   ← item 1
6. SSTI (CWE-94/1336)
7. SSRF (CWE-918)
8. Open Redirect (CWE-601)
9. Hardcoded Credentials (CWE-798)
10. Insecure Randomness in `def otp()` (CWE-330/338)   ← item 2
11. Sensitive Info Exposure (CWE-200)
12. Insecure Temp File `tempfile.mktemp()` (CWE-377)   ← item 3
13. Unsafe File Upload `f.save("uploads/"+f.filename)` (CWE-22/434)   ← item 4
14. Weak Crypto: `DES.new(...)`, `hashlib.new("md5",...)`, `ARC4.new(...)`   ← item 6
15. Debug Mode Enabled (CWE-489)

Must NOT be flagged (safe variants, prove no false positive):
- `"<h1>%s</h1>" % escape(request.args.get("x"))`
- `def otp(): secrets.randbelow(...)`
- `tempfile.mkstemp()`
- `f.save("uploads/" + secure_filename(f.filename))`
- `hashlib.md5(filename)` as a cache key
- `hashlib.sha256(pw)`

Then run the final gates and show me:
- `benchmark/run_benchmark_v2.py` = 100/100/0 (now with the new locked-in cases).
- The bundled WordPress re-scan finding count is unchanged from before this work
  (no new false positives introduced by items 4 and 6).
- A one-line confirmation that NO file outside the allowed scope (matchers +
  taint-engine source list + benchmark cases) was modified.

---

## 8) Summary of ownership (so you edit the right place)

| Item | What | Where (ONLY this) |
|---|---|---|
| 1 | XSS `%` formatting | `ReflectedXSSMatcher` regex |
| 2 | Insecure RNG by function name | `InsecureRandomnessMatcher` |
| 3 | Insecure temp file (new) | new `InsecureTempFileMatcher` |
| 4 | Upload path traversal | `core/taint_engine.py` SOURCE list (`.filename`) + `secure_filename` sanitizer |
| 5 | IDOR | **unchanged (intentional)** |
| 6 | Weak crypto | `WeakCryptoMatcher` (coverage + two tiers) |

Everything else in the codebase stays byte-for-byte the same. The engine's flow
logic, the wise verdict, the LLM layers, the CLI, and every other matcher are NOT
to be touched.

— end —
