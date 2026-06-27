# LogicBreaker AI — 21-Vulnerability Coverage Plan (fix + live-exploit)

Goal: for EACH of the 21 detected vulnerability classes, provide a real in-file
fix AND a live HTTP exploit probe, each correct and tested. Where a class cannot
be exploited over HTTP or auto-fixed without breaking code, use the best safe
remediation and say so honestly (never fake).

Legend: FIX = real in-file transform; EXPLOIT = live HTTP probe against the
running app; ✔ fully automatable; ◑ automatable with the safest standard
approach; ✖ honestly not safe to fully automate (best-effort remediation/probe).

| # | Vulnerability | FIX approach | EXPLOIT probe |
|---|---|---|---|
| 1 | SQL Injection | ✔ parameterized query / prepared stmt | ✔ tautology rows + auth bypass |
| 2 | OS Command Injection | ✔ replace shell call with arg-list / shlex.quote; shell=False | ✔ inject `;id` / `\|whoami`, detect uid output |
| 3 | Path Traversal | ✔ basename + realpath containment | ✔ read /etc/passwd via ../ |
| 4 | IDOR | ✔ ownership/authorization check | ✔ fetch other id without auth |
| 5 | Race Condition (TOCTOU) | ✔ lock/synchronized/mutex/transaction/flock | ✔ concurrent requests overspend |
| 6 | Broken Authorization | ✔ server-side role lookup | ✔ set role=admin param, detect escalation |
| 7 | SSRF | ◑ allowlist host + block internal IPs | ✔ point to 127.0.0.1 callback, detect fetch |
| 8 | XXE | ◑ disable DOCTYPE/external entities (defusedxml / secure features) | ✔ submit XML w/ external entity, detect file read |
| 9 | Insecure Deserialization | ◑ replace pickle/yaml.load with json/safe_load | ◑ send crafted payload, detect marker exec |
| 10 | Open Redirect | ✔ validate redirect target against allowlist | ✔ redirect to evil.com, detect Location |
| 11 | SSTI | ◑ render with sandbox / pass data as context not template | ✔ send `{{7*7}}`, detect 49 |
| 12 | Weak Cryptography | ✔ md5/sha1 → sha256; DES/RC4 → AES-GCM; bcrypt/argon2 for pw | ✖ inspect-only (can't always exploit over HTTP) |
| 13 | Hardcoded Secret | ◑ replace literal with os.environ.get(...) | ✖ inspect-only |
| 14 | JWT Weakness | ◑ enforce alg allowlist + verify=True | ◑ send alg=none token, detect acceptance |
| 15 | Mass Assignment | ◑ explicit field allowlist | ◑ post extra field is_admin, detect persisted |
| 16 | Missing Auth | ✔ add auth guard at handler top | ✔ call sensitive route w/o auth, detect success |
| 17 | Missing Rate Limit | ◑ add a simple in-process limiter decorator | ✔ flood N requests, detect no throttle |
| 18 | CORS Misconfig | ✔ replace `*`/reflected origin with allowlist | ✔ send Origin: evil, detect ACAO reflect |
| 19 | Price/Quantity Manipulation | ◑ server-side recompute / validate >=0 | ✔ send price=0 / negative, detect accepted |
| 20 | Negative/Zero Quantity | ✔ add quantity>0 validation | ✔ send qty=-5, detect accepted |
| 21 | Debug Mode | ✔ debug=False | ✔ trigger error, detect debugger/trace |

## Fix correctness rules (apply to every fixer)
- The transform must be syntactically valid in the target language.
- After applying, re-run the matcher: keep the fix ONLY if the finding is gone.
- Never bind a SQL fragment, never change a stored-hash scheme silently in a way
  that breaks existing data without a note, never strip auth logic.
- Multiple findings per function: re-read function from disk before each fix.
- If a safe transform isn't possible, return a precise RECOMMENDATION (no fake).

## Exploit correctness rules (apply to every probe)
- Launch a sandboxed copy; never touch the user's real files.
- Use a benign baseline vs an attack payload; only mark CONFIRMED when the attack
  demonstrably differs (extra data, executed marker, leaked file, reflected
  header, state change).
- Plant sentinels (files/markers) so proof doesn't depend on host specifics.
- Timeouts + clear evidence string on every probe.

## Execution order (each step: implement → unit-test → regression)
1. Fixers wave A (clearly safe): CmdInjection, Open Redirect, CORS,
   Negative/Zero Qty, Weak Crypto, Missing Auth.
2. Fixers wave B (safest-standard): SSRF, XXE, Insecure Deser, SSTI, JWT,
   Mass Assignment, Hardcoded Secret, Price Manip, Rate Limit.
3. Exploit probes wave A (clean HTTP tells): Cmd Injection, Open Redirect, SSTI,
   CORS, Negative Qty, Price Manip, Missing Auth, Debug Mode.
4. Exploit probes wave B: SSRF, XXE, JWT, Mass Assignment, Rate Limit,
   Insecure Deser.
5. Wire every probe into the coordinator with route classification.
6. Full regression: benchmark 100%, WordPress clean, self-scan 0 FP, and a
   combined demo where every fixable class goes find→exploit→fix→re-scan→0.

## Honesty ledger (what stays inspect-only / best-effort, and why)
- Weak Crypto, Hardcoded Secret: detectable + fixable in source, but not
  meaningfully exploitable via a single HTTP request → inspect-only proof.
- These are clearly labelled in output as static (not live) — never claimed as
  live-exploited.
