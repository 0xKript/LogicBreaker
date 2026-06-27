# LogicBreaker AI — Deep Analysis Engine Plan (Data Flow → Taint → Interprocedural → Cross-File)

These four capabilities are ONE layered system, not four independent features.
Each builds on the previous. We build bottom-up and test at every layer so we
never ship something that regresses precision (which must stay 100% on the
benchmark, 0 FP on self-scan, clean on WordPress).

## Why this is hard (honesty)
Today's matchers run regex over the TEXT of each function. Real data-flow needs a
proper walk of the tree-sitter AST: identify assignments, track which variables
hold tainted data, and see whether tainted data reaches a sink. We will add a
real (if focused) taint engine for PYTHON first (the language we test most),
keep regex matchers as a fallback for the other 12 languages, and never let the
new engine introduce false positives.

---

## LAYER 1 — Data Flow Analysis (the foundation)
Goal: within a single function, build a map of "this variable currently holds a
value derived from these other variables / expressions", by walking the AST.

1.1 Build an AST walker over the tree-sitter tree (Python first).
1.2 For each function, collect statements in order. For each assignment
    `target = expr`, record target ← set(names used in expr) + literal/call info.
1.3 Track reassignment (last definition wins at each point) — a simple
    flow-sensitive def chain, good enough for stra-line + simple branches.
1.4 Expose: `defs[var] = DataNode(sources=..., call=..., line=...)`.
Test: on `x = request.args.get('a'); y = x; z = y + '1'`, the chain resolves
`z` back to the request source.

## LAYER 2 — Taint Tracking (built on Layer 1)
Goal: mark values that originate from an untrusted SOURCE as tainted, propagate
taint through Layer-1 data flow, and detect when tainted data reaches a SINK
unsanitised.

2.1 SOURCE catalogue: request.args/form/json/values/headers/cookies, $_GET/$_POST,
    input(), argv, req.query/body/params, etc. (per language).
2.2 SINK catalogue per vulnerability class (already exists; reuse + structure):
    SQL execute(), os.system/subprocess(shell), open()/readfile(), redirect(),
    render_template_string(), yaml.load/pickle.loads, etc.
2.3 SANITISER catalogue per class: shlex.quote, parameterised query, int(),
    realpath+basename guard, allowlist checks, compare_digest, escapeshellarg.
2.4 Propagation rules: taint flows through assignment, concatenation, f-strings,
    .format(), most calls that pass the tainted value; taint is CLEARED by a
    recognised sanitiser appropriate to the sink class.
2.5 A finding fires when a tainted value reaches a sink with no class-appropriate
    sanitiser between source and sink.
Test: tainted `host` reaching `os.system` fires; `shlex.quote(host)` clears it.

## LAYER 3 — Interprocedural Analysis (taint across function calls)
Goal: if function A passes a tainted value into function B, and B's parameter
reaches a sink, flag it — tracking taint across the call boundary.

3.1 Build a call graph: which functions call which (by name), and which argument
    positions carry tainted values at the call site.
3.2 Build per-function parameter→sink summaries: "if param p_i of B is tainted,
    it reaches a <class> sink unsanitised." (a function "taint summary").
3.3 At a call site `B(tainted_arg)`, if the matching parameter has a sink summary,
    propagate: the caller is now vulnerable too.
3.4 Bound the depth (e.g. 3 hops) and guard against recursion cycles.
Test: `def handler(): q=request...; run_query(q)` + `def run_query(s): db.execute(s)`
flags SQLi even though source and sink are in different functions.

## LAYER 4 — Cross-File Analysis (taint across modules)
Goal: resolve calls whose target function lives in another file, so taint
summaries from Layer 3 work across imports.

4.1 Build a global symbol table: function qualname -> its unit (file, AST, summary).
4.2 Resolve imports/calls to a function defined in another file (best-effort by
    name; handle `from m import f` and `import m; m.f()`).
4.3 Reuse Layer-3 propagation using the global table, so a tainted arg passed to
    a function defined elsewhere is followed into that file.
4.4 Bound work for large repos (hundreds of files): cache summaries, cap hops,
    skip third-party/vendor dirs.
Test: source in routes.py calls a helper in db.py whose body has the sink -> flagged.

---

## Integration & safety (applies to all layers)
- The taint engine produces findings in the SAME shape as existing matchers, so
  reporting/fixing/live-exploit all work unchanged.
- Run the taint engine ALONGSIDE existing matchers; DEDUPLICATE findings (same
  type+file+line) so we don't double-report.
- Confidence: taint-derived findings (source→sink proven) get HIGHER confidence
  than text-pattern findings.
- PRECISION GATE after every layer: benchmark must stay 100% precision/recall,
  self-scan 0 FP, WordPress core clean, the user's 4-vuln file still = 4, the
  16-vuln app still find→fix→0. If a layer regresses precision, it's gated off
  until fixed.
- Performance: cap per-file work, cache ASTs and summaries, skip vendor dirs;
  must still scan hundreds of files in seconds.

## Build order (each: implement → unit test → full regression)
1. Layer 1 (data-flow map, Python) + tests.
2. Layer 2 (taint source→sink, Python) + tests; wire as a matcher; dedupe.
3. Regression gate. If green, continue.
4. Layer 3 (call graph + summaries, intra-file first) + tests.
5. Layer 4 (global symbol table, cross-file) + tests.
6. Final regression + scale test (hundreds of files) + package.

## Honesty ledger
- The taint engine targets PYTHON deeply; other languages keep the regex matchers
  (still solid, as proven on the PHP plugin CVEs). We will say this clearly.
- This is a focused taint engine, not a full abstract-interpretation framework;
  it handles the common real-world shapes (assignments, concat, f-strings, calls)
  and is bounded for performance. We won't claim it rivals CodeQL's completeness.
