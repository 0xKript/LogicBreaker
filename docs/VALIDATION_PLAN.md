# LogicBreaker AI — Validation & Completion Plan (real CVEs + 20 fixers + live probes)

This plan has THREE deliverables, each measured with real numbers, no claims.

## Part A — Prove detection accuracy on REAL WordPress plugins with known CVEs
Goal: download actual vulnerable plugin code (versions with documented CVEs) and
measure: did we find the known vuln? did we name/classify/severity it right? how
many false positives?

A1. Pick plugins with well-documented, code-visible vulnerabilities, e.g.:
    - SQL injection in a plugin's query handler
    - Path traversal / arbitrary file read
    - Missing authorization / privilege escalation
    - CSRF / open redirect
   Source the exact vulnerable file(s) from the plugin's public source at the
   vulnerable version tag (raw GitHub / SVN trunk at that revision).
A2. Run ScanEngine on each plugin file/dir.
A3. For each known CVE: record FOUND / MISSED, and whether the type+CWE+severity
    match the CVE class. Record extra findings and judge FP vs legitimate.
A4. Report a table: plugin | known vuln | detected? | correct class? | FPs.
A5. Honesty: if we miss a known vuln, say so and explain why (and fix the
    detector if it's a real gap, not just tune to the test).

## Part B — Verify all 20 in-file fixers actually CLOSE the vuln
Goal: for each of the 20 fixer-backed types, take a vulnerable sample, fix it,
re-run the matcher, and confirm the finding is gone. Already at 20/20 on unit
samples; now also prove it end-to-end through the real pipeline (scan → fix →
re-scan = 0) on a combined multi-vuln app, and confirm no fix breaks Python
syntax (compile() the patched file).

B1. Build one app containing every fixable class.
B2. Run `--fix`; assert each applied patch is syntactically valid (py_compile).
B3. Re-scan; assert all fixable types are closed.
B4. Restore from backup; assert vulns return (proves backup correctness).

## Part C — Add live-exploit probes for every class that is HTTP-exploitable
Goal: grow live probes from 5 to every class that can be proven over HTTP.
HTTP-exploitable (add probes): Command Injection, SSTI, Open Redirect, CORS,
SSRF, Missing Auth, Negative Qty, Price Manipulation, Mass Assignment, XXE,
Debug Mode, (plus existing Race, IDOR, SQLi, SQL-auth-bypass, Path Traversal).
NOT HTTP-exploitable (stay static, labelled honestly): Weak Crypto, Hardcoded
Secret, JWT-weakness (config-level), Insecure Deserialization (needs a gadget).

C1. Implement each probe: benign baseline vs attack payload; CONFIRMED only on a
    real differential (executed marker, reflected header, leaked file, redirect
    Location, accepted bad value, state change).
C2. Plant sentinels where needed (files, markers) so proof is host-independent.
C3. Wire each probe into the coordinator with route classification.
C4. Test each probe against a deliberately-vulnerable app; confirm it fires, and
    against a fixed app; confirm it does NOT fire (no false CONFIRMED).

## Cross-cutting invariants (must hold after every change)
- benchmark precision/recall = 100%
- WordPress core sample = only legitimate findings (no FP flood)
- self-scan = 0 false positives
- every applied fix compiles and closes its finding
- no probe reports CONFIRMED on safe code

## Execution order
1. Part B end-to-end (fast, builds confidence the fixers are solid).
2. Part C probes wave 1 (clean HTTP tells): Cmd Injection, SSTI, Open Redirect,
   CORS, Negative Qty, Price Manip, Missing Auth, Debug Mode.
3. Part C probes wave 2: SSRF, XXE, Mass Assignment.
4. Part A real-CVE WordPress plugin validation (the headline proof).
5. Full regression + package + fresh-extract verification.

## Honesty ledger
- Live exploitation covers HTTP-exploitable classes only; ~15 of 21. The rest
  are detected + fixed + given a recommendation, never falsely "exploited".
- Real-CVE results are reported as-is, including any misses.
