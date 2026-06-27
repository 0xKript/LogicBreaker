# LogicBreaker AI — Hardening Plan (anti-overfit + multi-language taint + real patches)

This plan answers three valid critiques and one feature request, in priority
order. Each item: implement -> unit test (incl. the exact bypass cases raised)
-> full regression (precision must stay 100%, self-scan 0 FP).

## CRITIQUE 1 (highest priority) — Sanitiser overfitting -> FALSE NEGATIVE
Problem: the engine treats `shlex.quote(x)` as "clean" by substring, so
`return shlex.quote(x) + "; rm -rf /"` is wrongly considered safe (an attacker
appends a shell command AFTER the quoted part).

Fix:
1.1 A sanitiser only cleans the EXACT value it wraps. If the sanitised value is
    then concatenated with attacker-influenced OR command-bearing text, taint is
    RE-INTRODUCED. Concretely: an expression is clean only if it is EXACTLY a
    sanitiser call on the tainted value, not a larger expression containing it.
1.2 For command sinks specifically: even a constant suffix like `"; rm -rf /"`
    after a quoted value is dangerous, because the shell still parses the
    metacharacters in the constant. So: if a command sink's argument contains a
    shell-metacharacter-bearing constant concatenated with anything, flag it.
1.3 Re-test the exact bypasses:
    - `return shlex.quote(x) + "; rm -rf /"`  -> MUST flag
    - `return shlex.quote(x)`                  -> MUST NOT flag
    - `safe = shlex.quote(host); os.system("ping "+safe)` -> MUST NOT flag (the
      constant has no metacharacters and safe is fully quoted)

## CRITIQUE 2 — Interprocedural depth / return-taint precision
Problem: return-taint is "simple". Strengthen without claiming CodeQL parity.

Fix:
2.1 Compute a real per-function RETURN-TAINT summary: "given tainted param p,
    is the returned value tainted (unsanitised)?" using the same flow engine,
    not a heuristic. Already started; make it exact w.r.t. 1.1/1.2.
2.2 Propagate return-taint through assignments at call sites:
    `cmd = build(host)` taints `cmd` iff `build` returns taint for that arg.
2.3 Bound recursion and cap call-depth (e.g. 5) with a visited-set to avoid
    cycles / path explosion. Be explicit this is bounded, not exhaustive.
2.4 Honesty: no alias analysis, no full path-sensitivity. Document it.

## CRITIQUE 3 + FEATURE — Multi-Language Taint Engine
Problem: taint is Python-only. Extend the SAME AST-based engine to the other
high-value languages using tree-sitter (already loaded for 13 languages).

Fix:
3.1 Generalise the engine: the walk is AST-based; only the node-type names and
    the source/sink/sanitiser catalogues differ per language. Add per-language
    tables for: JavaScript/TypeScript, PHP, Java, Ruby, Go.
3.2 Per language: SOURCES (req.query/body, $_GET, request.getParameter, params),
    SINKS (db.query/execute, child_process.exec, system/shell_exec, Runtime.exec,
    os/exec.Command, eval), SANITISERS (parameterised queries, escapeshellarg,
    PreparedStatement, etc.).
3.3 Start with JS + PHP (most web-relevant), then Java/Ruby/Go. Each: unit tests
    for a true positive AND a sanitised true negative.
3.4 Honesty: depth per language varies; Python + JS + PHP deepest. Document.

## FEATURE — Advanced Auto-Patch Engine (real, correct fixes)
Problem: fixes must actually work, be valid, and close the vuln — including the
interprocedural case where the sink is in another function.

Fix:
4.1 Patch at the SINK, not the call site. When taint analysis flags a flow, the
    fix is applied in the function that contains the actual dangerous sink (e.g.
    add shlex.split/parameterisation in run_command), which is where it belongs.
4.2 Every patch is validated by: (a) re-running the detector incl. taint -> the
    flow must be gone; (b) the file must still COMPILE and IMPORT (no NameError);
    (c) for live targets, re-attack must fail.
4.3 If no safe in-place fix exists, emit a precise recommendation (never break
    code, never fake).
4.4 Re-verify the whole repo after patching: re-scan -> 0 fixable remain.

## Cross-cutting invariants (gate after EVERY change)
- benchmark precision/recall = 100%; self-scan 0 FP; WordPress core clean.
- the 4 bypass/precision cases above all behave correctly.
- user's chain file still flags the real CmdInjection; the sanitised variant does
  NOT flag.
- performance: hundreds of files in seconds; bounded depth; skip vendor dirs.

## Build order
1. Fix sanitiser overfitting (1.1-1.3) + tests. <-- start here (it's a real FN)
2. Strengthen return-taint precision (2.1-2.3) + tests.
3. Multi-language taint: JS, then PHP, then Java/Ruby/Go + tests each.
4. Auto-patch at sink + full verify + re-scan-to-zero.
5. Full regression + scale test + package + fresh-extract verify.

## Honesty ledger (what we will and won't claim)
- This is a strong, bounded, multi-language taint engine with real return-taint
  and sink-targeted patching. It is NOT CodeQL: no alias analysis, no full path
  sensitivity, bounded call-depth. We say so plainly.
- Languages have different depth; we list which are deepest.
- Patches that can't be made safely become recommendations, not edits.
