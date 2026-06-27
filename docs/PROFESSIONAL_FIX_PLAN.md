# LogicBreaker AI — Professional Fix + Real Verification + Per-Language Engines

Every point below is a real defect the user identified. Build order is by
severity. Each item: implement -> REAL test (run the patched code, re-attack
live) -> regression (precision 100%, self-scan 0 FP).

## P0 — The fix must CLOSE the real vulnerability (root cause), professionally
Problem: command-injection "fix" left shell=True->False but the tainted f-string
still flows in; and the LLM path used blacklist replace(';','') which is weak AND
sometimes wasn't even written to the file. The report claimed "fixed" while the
file still had the vuln.

Requirements:
- Command injection: the professional fix is to REMOVE the shell and pass an
  ARGV LIST. For the chain build_command()->run_command(), the fix must rewrite
  so the command is a list and no shell is used. Concretely transform:
      cmd = f"ping -c 1 {host}"              (build_command)
      subprocess.check_output(command, shell=True)   (run_command)
  into a safe form that actually runs and cannot inject. The cleanest correct
  transform that preserves the call-graph: build_command returns an ARGV LIST
  (["ping","-c","1",host]) and run_command calls subprocess.check_output(command)
  with NO shell. This kills the vuln at the root.
- SQLi: parameterised query (placeholder + bound params), not int() hacks or
  string filtering.
- NEVER blacklist/replace()-based sanitisation as a "fix". Remove it from the
  fixer entirely.
- The fixer must verify the patch by RE-PARSING the file and RE-RUNNING taint:
  the flow must be GONE. If not gone -> the fix is rejected (not reported fixed).

## P0 — Real post-fix verification (no fake "all closed")
Problem: re-scan said "all auto-fixable closed" while CmdInjection remained,
because the engine only checked auto-fixable types and the patch didn't actually
close it.

Requirements:
- After applying patches, RE-SCAN the real files on disk (static + taint).
- For every finding that was CONFIRMED live, RE-LAUNCH the app and RE-ATTACK with
  the SAME payload. The vulnerability is only "closed" if the live re-attack now
  FAILS. If it still succeeds -> report STILL VULNERABLE, attempt a stronger fix,
  re-verify; loop up to N times; if still open, say so honestly.
- The "all closed" message may ONLY print when the re-scan AND live re-attack both
  show zero remaining for that finding.

## P0 — UX: show Results table FIRST, then ONE batched fix question
Problem: it asked per-finding BEFORE showing results.
Requirements:
- Print the full Results table + live-exploit summary FIRST.
- Then ask ONE question: "Fix all N vulnerabilities? [y/n]". If yes -> fix ALL.
- No per-finding prompts.

## P1 — Fix + live exploit must work in --fast mode too
Problem: dynamic exploitation + patch verification skipped under fast scan.
Requirements:
- --fast may reduce LLM triage depth, but MUST still run: live exploitation and
  patch verification (the find->exploit->fix->re-verify loop).

## P1 — Per-language taint engines (not regex) for PHP, JS, TS, Java, Go
Problem: only Python had a real engine. Others leaned on regex matchers.
Requirements:
- Promote the generic AST taint pass into a proper per-language engine with: real
  source tracking, intra-function data flow, sink detection, sanitiser awareness,
  and (where feasible) interprocedural + return-taint — for PHP, JS, TS, Java, Go.
- Each language: unit tests for a true positive, a sanitised true negative, and a
  cross-function case.

## P2 — Stronger dynamic exploitation (smarter, planned, more classes)
Problem: dynamic part is the weakest vs the project's ambition.
Requirements:
- Add more probes and smarter payloads; make probes adapt (try multiple payloads,
  confirm via differential / markers / out-of-band-ish signals).
- A clear plan: detect class -> choose payloads -> attack -> confirm -> (after
  fix) re-attack to prove closed.

## Cross-cutting invariants (gate after EVERY change)
- benchmark precision/recall = 100%, self-scan 0 FP, WordPress core clean.
- the chain file: CmdInjection detected AND fixed at root (shell removed, argv
  list), re-attack fails after fix, file actually changed.
- bypass cases (quote + metacharacters) still detected.
- patched code compiles AND imports AND runs.

## Build order
1. P0 fix engine: command injection root-cause fix (chain-aware), remove blacklist.
2. P0 real re-verification loop (re-scan + live re-attack; honest messaging).
3. P0 UX: results-first, single batched question.
4. P1 fast-mode: enable dynamic + verification.
5. P1 per-language engines (PHP, JS, TS, Java, Go) + tests.
6. P2 stronger dynamic exploitation.
7. Full regression + scale + package + fresh-extract verify.

## Honesty ledger
- We patch the root cause (remove shell, argv list / parameterised query). We do
  NOT use blacklist filtering.
- Verification re-runs the real detector AND re-attacks live; "closed" means
  proven closed, not assumed.
- Per-language engines are real AST taint trackers; depth still varies by language
  but all get true data-flow + sink + sanitiser awareness, not just regex.
