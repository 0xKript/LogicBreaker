# LogicBreaker AI — Master Plan (hierarchical, end-to-end)

The tool's promise, in order: **DETECT → PROVE (live exploit) → ASK → FIX (in-file)
→ RE-VERIFY → BACK UP**. Every layer below serves that promise. This document is
the source of truth for what each layer must do and how we verify it.

## Layer 0 — Inputs
- Accept any folder/path of source code (1 file or 10,000).
- Detect language per file (21 languages).
- Never require a demo; the user points at their own code.

## Layer 1 — DETECTION (static, must be precise)
Goal: name the vulnerability, its CWE, its severity, and its exact location —
correctly, with low false positives AND low false negatives.

1.1 Parse each file into functions/methods (tree-sitter) + a synthetic
    `<module>` unit for top-level code (so `app.run(debug=True)` is visible).
1.2 Extract HTTP routes (multi-framework) and LINK them to their handler
    functions by line proximity, so handler-aware matchers fire on decorated
    handlers (`@app.route("/user/<id>")`).
1.3 Run matchers. Each matcher must require:
    - reachability (real request handler / real sink), not just a keyword;
    - the dangerous construct as EXECUTED code, not a string/comment;
    - recognition of framework-safe patterns (trusted table names, sanitizers).
1.4 Context-filter pass: drop findings that are genuinely inside strings/
    comments/regex tables, drop pattern-findings in the scanner's OWN detector
    files, penalize test files — WITHOUT dropping real sink calls or f-strings
    with interpolation (those are dynamic = dangerous).
1.5 Severity must be logically correct and consistent:
    - CRITICAL: SQL injection, command injection
    - HIGH: path traversal, IDOR, SSRF, broken auth, insecure deserialization
    - MEDIUM: open redirect, CORS, mass assignment, weak crypto, missing rate limit
    - LOW: debug mode, verbose errors
Verify: benchmark precision/recall = 100% on labelled corpus; WordPress core
yields only legitimate review-items; self-scan yields 0 false positives.

## Layer 2 — LIVE EXPLOITATION (the "real proof", must actually run)
Goal: launch a sandboxed copy of the app and reproduce the vulnerability with a
real request/response, turning STATIC_FINDING into CONFIRMED.

2.1 Runtime detection: find every installed language runtime on the host.
2.2 Universal launcher: start the app in WHATEVER language it's written in,
    provided that runtime is installed (Python/Node/PHP/Ruby/Go today).
2.3 **Port injection (critical):** the app must listen on the sandbox's chosen
    port REGARDLESS of how it's written. We do NOT rely on the app reading
    argv. For Python we generate a bootstrap that imports the user's module and
    runs its Flask/FastAPI app object on our port, with a fallback monkeypatch
    of app.run/SocketServer. Same idea per language.
2.4 Make the app self-contained enough to boot: provide a temp working dir,
    tolerate a missing DB by allowing the app to create it, set env defaults.
2.5 Probes per vulnerability class, against the running app:
    - Race (TOCTOU): N concurrent requests; detect overspend / floor-breach.
    - IDOR: request sequential object IDs without auth; detect cross-tenant data.
    - SQL injection: benign value vs tautology payload; detect extra rows / error
      / auth bypass.
    - Path traversal: request `../` payloads; detect file contents leaking.
    - Debug mode: trigger an error; detect debugger/stack trace in response.
2.6 Record a real PROOF: the request sent, the response observed, and the
    before/after state. Status becomes CONFIRMED only when the probe truly
    demonstrates the flaw.
Verify: on a launchable app, race drains balance below zero, IDOR returns another
user's record, SQLi tautology bypasses login — all shown live.

## Layer 3 — ASK (the user's decision)
Goal: after detection (+ proof where possible), ask per vulnerability whether to
fix. Interactive runs always ask — no flag needed. Decline → record location,
type, severity, count; leave code untouched. Accept → fix.

## Layer 4 — FIX (real, in-file, verified)
Goal: rewrite the actual source file to close the vulnerability — not a comment.
4.1 Per-class fixers:
    - SQLi → parameterized query / prepared statement (handles concat, f-string,
      assigned-then-executed, multiline, PHP $wpdb->prepare, JS template).
    - IDOR → ownership check after load, or authorization check on the path-param.
    - Broken auth → server-side role lookup (no client-supplied role).
    - Race → lock/synchronized/sync.Mutex/transaction/flock per language.
    - Path traversal → basename + realpath containment under a safe base.
    - Debug mode → debug=False.
4.2 Multiple findings per function: re-read the function from disk before each
    fix so fixes don't clobber each other.
4.3 Honesty: if a construct can't be safely auto-fixed (e.g. a variable holding
    a SQL fragment, or a value needing infra like a rate limiter), DON'T fake a
    fix — leave a precise recommendation.
4.4 Every fix is VERIFIED: re-run the detector (and re-attack, for live targets)
    on the patched code; keep the fix only if the vulnerability is gone.

## Layer 5 — RE-VERIFY (prove closure)
Goal: after applying fixes, re-scan the whole target. Report how many issues are
closed. If fixable issues remain, run one more fix pass. Remaining items must be
only the honestly-unfixable advisories. A user re-scanning later sees the
fixable vulnerabilities gone.

## Layer 6 — BACKUP / RESTORE (safety)
Goal: before ANY file write, copy the original to
`<target>/.logicbreaker_backups/<timestamp>/` with a manifest. One command rolls
back everything. Must handle hundreds of files.

## Layer 7 — REPORTING
Goal: dark-themed HTML + PDF; per-finding type, CWE, severity, location, proof,
fix status, and remediation. Console shows the same, plus the re-scan result.

## Layer 8 — API / LLM (optional enrichment)
Goal: optional LLM triage. Validate the API key LIVE (format + provider ping)
before use; reject empty/garbage/wrong-provider keys; tolerate paste on Windows
(visible input). Never block the core (fast scan works with no key).

## Cross-cutting invariants
- No demo models shipped.
- Concise, correct, honest output. Never claim a fix/exploit that didn't happen.
- Re-test after every change: benchmark 100%, WordPress clean, self-scan 0 FP,
  full DETECT→FIX→RE-SCAN reaches 0 fixable on real code.
