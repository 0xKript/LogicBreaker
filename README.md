# LogicBreaker AI

**A multi-language business-logic vulnerability hunter that finds flaws, *proves* them by live exploitation, and *auto-patches* them — then re-runs the attack to verify the fix actually holds.**

Most "AI security" tools stop at an opinion: they ask a model whether some code looks vulnerable. LogicBreaker AI goes further — for the classes it supports dynamically, it launches a sandboxed copy of your app, runs a real attack, measures the outcome, applies a fix, and attacks again to confirm the fix worked.

---

## What makes it different

| Capability | LogicBreaker AI |
|---|---|
| Detects business-logic flaws (race conditions, IDOR, price/quantity abuse, broken auth) | ✅ |
| **Proves** them with live exploitation against a running copy | ✅ Python (Flask/FastAPI) + Node.js (Express); PHP when `php` CLI present |
| **Auto-patches** and **re-verifies** by re-attacking | ✅ (Python race conditions) |
| Multi-language static analysis on a real parser (tree-sitter) | ✅ (21 languages) |
| Pluggable detectors — add a new vuln type in one file | ✅ |
| Works fully offline (no API key required) | ✅ |
| Optional LLM triage across 10 providers | ✅ |
| HTML + PDF reports | ✅ |
| GitHub PR automation + CI/CD gates | ✅ |
| **Measured accuracy** (precision/recall benchmark) | ✅ `python benchmark/run_benchmark.py` |

---

## Honest capability tiers

LogicBreaker AI is deliberately transparent about *how strong* each result is. Three levels:

### 1. CONFIRMED (live-proven)
The vulnerability was reproduced against a **running** sandboxed copy of your app:
- **Race conditions (TOCTOU)** — fires N concurrent requests and detects overspend / floor-breach.
- **IDOR** — requests sequential object IDs with no auth and detects cross-tenant data exposure.
- **SQL injection** — compares a benign value vs a tautology payload and detects extra rows / DB errors.

**Universal runtime-aware live exploitation.** The engine launches the target in
**whatever language it is written in, as long as that language's runtime is
installed on the machine.** It auto-detects installed runtimes and drives them —
five languages or a hundred, whatever you have. Built-in web-app launchers cover
**Python (Flask/FastAPI), Node.js (Express/raw http), PHP, Ruby (Sinatra/WEBrick),
and Go** today; all five have been verified by reproducing real exploits live.
Run `python main.py --list-runtimes` to see what your machine supports.

When a language's runtime is **not** installed, the tool still performs full
static detection and produces a correct patch — it simply can't run the live
attack for that language until you install its runtime (no tool changes needed).
We can't ship a compiler/interpreter for every language (those are large programs
built by their own communities), but we detect and drive whatever is present.

### 2. VERIFIED_FIX (patched and re-tested)
For **Python race conditions**, the tool injects a real lock via Python AST surgery, applies the patch to a fresh sandbox copy, **re-runs the exact same attack**, and keeps the patch *only if the attack now fails*. Otherwise it rolls back (`AUTO_FIX_FAILED`). This is a genuine fix-verification loop, not a suggestion.

### 3. LANGUAGE_PATCH (real, correct synchronization for other languages)
For race conditions in **Java, Go, C#, Ruby, JavaScript/TypeScript, and PHP**, the tool generates a **real, syntactically-correct synchronization patch** — `synchronized` (Java), `sync.Mutex` with `defer Unlock()` (Go), `lock(_sync){}` (C#), `@mutex.synchronize` (Ruby), an async-mutex `runExclusive` wrapper (JS/TS), or a DB transaction with commit/rollback (PHP). These are correct fixes a developer can apply directly. They are labelled *not live-verified* because verifying them requires that language's runtime + build to be present (live re-attack verification currently runs for Python, and for Node.js/PHP targets when their runtime is installed).

### 4. STATIC_FINDING (heuristic, confidence-scored)
Cross-language detection over real syntax trees (tree-sitter). Race detection requires *a real conditional guard + a state mutation on the same variable + a genuine latency/commit window + no existing lock*, and ignores `=>`/`->` arrows, constructors, and pure client-side library code — which is what keeps the false-positive rate low on large real codebases. Every finding carries a confidence score.

## Safety: real in-file fixes, re-verification, backups, and restore

The tool follows the model **find → exploit → ask → fix → re-test**, and a fix
is a **real edit to your source file** — not a comment or a suggestion:

- **`--interactive-fix`** — after each vulnerability is found (and live-exploited
  where possible), you are asked in plain English *"Do you want to fix this
  vulnerability? [Y/n]"*. Answer **no** and it is left untouched, but its
  location, count, and classification are still recorded. Answer **yes** and the
  tool rewrites the vulnerable code in place.
- **Real fixes, verified.** SQL injection is rewritten to a parameterized query;
  IDOR gets an ownership check; client-trusted roles are replaced with a
  server-side lookup; race conditions get a real lock/`synchronized`/`sync.Mutex`/
  transaction/`flock`. Every fix is **re-verified** — the tool re-runs the
  detector (and re-attacks, for live targets) on the patched code and only keeps
  the fix if the vulnerability is genuinely gone. **A re-scan of a fixed file
  reports zero findings**, because the flaw is actually closed, not masked.
- **`--fix`** — applies the verified fixes to the real source files.
- **Automatic backups.** Before **any** file is modified, the original is copied
  to `<target>/.logicbreaker_backups/<timestamp>/` with a `RESTORE_MANIFEST.json`.
  Patch 500 files and all 500 originals are saved. Roll everything back with:
  ```bash
  python -m core.backup_manager restore "<target>/.logicbreaker_backups/<timestamp>"
  ```

---

## Language support

Parsing is backed by **tree-sitter** (real concrete syntax trees, not regex), using the maintained per-language `tree-sitter-<lang>` packages and the modern tree-sitter API. **Works on Python 3.12 / 3.13 / 3.14+.**

Two tiers:

- **DEEP** (hand-tuned extractors): Python, JavaScript, TypeScript/TSX, Java, Go, PHP, C#, Ruby.
- **PARSED** (generic function extraction + cross-language matchers): C, C++, Rust, Kotlin, Scala, Bash, Lua, SQL, HTML, CSS, JSON, YAML — and any other grammar you install.

`requirements.txt` installs ~21 grammars out of the box. To add another mapped language, just `pip install tree-sitter-<lang>` — the tool auto-detects it. Run `python main.py --list-languages` to see which grammars are installed (●) vs available to add (○). 200+ file extensions are mapped.

> **Honest note:** "DEEP" means the structural signals the matchers rely on are tuned for that language. "PARSED" means we build a real syntax tree and extract functions, then apply the language-agnostic matchers — useful coverage, labelled as generic so you don't mistake it for the deep path.

---

## Vulnerability detectors (21 built-in)

CWE-367 Race Condition (TOCTOU) · CWE-840 Price/Quantity Manipulation · CWE-639 IDOR · CWE-89 SQL Injection · CWE-602 Broken Authorization · CWE-840 Negative/Zero Quantity · CWE-798 Hardcoded Secret · CWE-307 Missing Rate Limit · CWE-78 OS Command Injection · CWE-22 Path Traversal · CWE-1336 SSTI · CWE-327 Weak Crypto · CWE-601 Open Redirect · CWE-915 Mass Assignment · CWE-611 XXE · CWE-502 Insecure Deserialization · CWE-306 Missing Auth · CWE-489 Debug Mode · CWE-942 CORS Misconfig · CWE-347 JWT Weakness · CWE-918 SSRF (plugin example).

Run `python main.py --list-matchers`.

### Adding your own detector (plugin system)
Drop a file in `matchers/plugins/` exposing a `MATCHERS` list of `BaseMatcher` subclasses. It's auto-discovered at startup — **no engine changes**. See `matchers/plugins/example_ssrf.py`.

---

## Install

```bash
pip install -r requirements.txt
```

Python 3.10+ (including 3.12 / 3.13 / 3.14). For scanning/running FastAPI targets, also `pip install fastapi uvicorn`.

> On Windows, if `pip` isn't recognized, use `python -m pip` (or `py -m pip`).

---

## Usage

### Interactive (recommended)
```bash
python main.py
```
You'll be asked: fast scan vs API → (if API) pick a provider → enter your key → target path.

### Non-interactive / scripts
```bash
# Fast scan (no API key), full pipeline
python main.py --target ./my_project --fast --non-interactive

# With LLM triage
python main.py --target ./my_project --provider groq --api-key $GROQ_API_KEY

# Static only (no run, no patch) — fastest, safe for any codebase
python main.py --target ./repo --fast --no-dynamic --no-patch

# Limit scope on huge repos
python main.py --target ./monorepo --fast --max-files 2000 --max-file-bytes 800000
```

### Find → exploit → ask → fix → re-verify
```bash
# Ask yes/no before fixing each vulnerability (originals are backed up first)
python main.py --target ./app --fast --interactive-fix --fix

# Apply all verified fixes non-interactively (still backs up every original)
python main.py --target ./app --fast --non-interactive --fix

# Roll back every applied fix
python -m core.backup_manager restore "./app/.logicbreaker_backups/<timestamp>"
```


### Reports & patches
```bash
python main.py --target ./app --fast --out report_dir \
  --html report_dir/scan.html --pdf report_dir/scan.pdf --json report_dir/findings.json
```

### GitHub PR & CI
```bash
# Export patches + a PR body (no network)
python main.py --target ./app --fast --export-patches

# Open a PR automatically (needs GITHUB_TOKEN and a git repo target)
GITHUB_TOKEN=ghp_xxx python main.py --target ./app --fast --open-pr --pr-base main

# Generate CI templates (GitHub Actions / GitLab CI / pre-commit)
python main.py --init-ci --target ./app
```

The CLI exits non-zero when CRITICAL/HIGH findings exist, so it works as a CI gate out of the box.

---

## API providers (for optional triage / LLM fixes)

Anthropic Claude · OpenAI · Google Gemini · Groq · Mistral · DeepSeek · Together · OpenRouter · xAI Grok · Cohere.

The core (detection + live exploitation + verified patching) **does not require any API**. LLMs only add triage, enrichment, and suggested rewrites for classes without a deterministic fix.

---

## How it works (pipeline)

```
  scan tree ─▶ tree-sitter parse ─▶ extract functions + routes
      │                                   │
      ▼                                   ▼
  run 21 matchers ──▶ static findings ──▶ (optional) LLM triage
      │
      ▼
  launch target in sandbox ─▶ live probes (race / IDOR / SQLi)
      │                                   │
      ▼                                   ▼
  link proofs to findings  ──▶ CONFIRMED
      │
      ▼
  Healer: inject fix ─▶ re-attack patched copy ─▶ VERIFIED_FIX | rollback
      │
      ▼
  HTML + PDF report  ·  .patch files  ·  optional GitHub PR
```

The sandbox makes an **ephemeral copy** of the target and runs it as a subprocess on a free port; nothing touches your original files. Patches are written as unified diffs — they are never silently applied to your source.

---

## Architecture

```
languages/    registry (ext→lang) + tree-sitter universal parser
matchers/     base + signals + builtin + extended + plugin loader
scanners/     recursive file scanner, multi-framework route extractor,
              dynamic tester (live probes), dynamic coordinator
sandbox/      ephemeral sandbox manager (Flask & FastAPI launch)
agents/       multi-provider LLM client, universal healer
reporting/    HTML + PDF report generators
integrations/ GitHub PR automation, CI/CD templates
core/         scan engine + orchestrator + backup manager
cli/          rich UI + interactive startup flow
agents/       healer, in-file code fixer, language patches, LLM client
benchmark/    labelled accuracy corpus + runner
```

---

## Measured accuracy

Run the bundled labelled benchmark to see precision/recall on a corpus of
known-vulnerable and known-safe files (the safe set is full of look-alikes:
parameterized queries, locked critical sections, UI text containing the word
"Select", detection regexes, comments that merely mention vulnerabilities):

```bash
python benchmark/run_benchmark.py
```

It reports True/False Positives & Negatives, **Precision**, **Recall**, and
**False-Positive Rate**. Add your own cases under `benchmark/cases/vulnerable/`
and `benchmark/cases/safe/` to measure against your own code.

> **On false-positive rate (important):** a *healthy* scanner on real, diverse
> code typically lands around **5–15%** false positives. A tool reporting **0%
> on real code is usually a red flag** — it means it is too conservative and is
> silently missing real issues. The bundled corpus is small and clean, so it
> can score 100%; that is a sanity check, **not** a claim of perfection. Always
> measure on real projects before trusting any number.

## Roadmap (honestly not done yet)

These are real engineering efforts, deliberately **not** faked as working:

- **Live exploitation for more runtimes** — today: Python (Flask/FastAPI) and Node.js (Express), plus PHP when the `php` CLI is present. Java/Go/Ruby runtime exploitation needs per-runtime launchers + build steps and is non-trivial.
- **Verified auto-fix beyond Python race conditions** — other classes/languages currently get deterministic patches or LLM suggestions, not a re-tested fix loop.
- **Taint / data-flow analysis** — to push precision higher on injection classes (today's matchers are precise co-occurrence heuristics, not full data-flow).
- **A large, third-party benchmark corpus** — the bundled one is a starter; real validation needs hundreds of diverse real-world cases.
- **Deep extractors for the remaining PARSED languages** — to raise their findings from generic to high-confidence.
- **Real database integration (Redis/PostgreSQL/MySQL)** for stateful exploitation that spans a datastore.

## Path to production / government use (what this tool is and is NOT)

This is a **genuinely working tool** with measured accuracy — strong enough to
demonstrate, pilot, and build on. It is **not** a certified, production-grade
security product for critical/government infrastructure *yet*, and shipping it
as one would be irresponsible. Reaching that bar requires work that **cannot be
written as code** and must be done by people and institutions:

1. **Independent security review** — an *external* team audits the tool. By
   definition this can't be self-authored. See `docs/SECURITY_REVIEW_TEMPLATE.md`
   for a checklist of what such a review should cover.
2. **Validation at scale** — run against hundreds of real codebases and measure
   precision/recall/coverage, not a bundled demo corpus.
3. **Certification & accreditation** — formal processes (issued by the relevant
   authorities) that take months.
4. **Legal & liability coverage** — insurance, contracts, a legal entity.

Presenting it honestly as a *working research tool / functional prototype with
a verified-exploitation engine and measured accuracy* is credible and strong.
Claiming certified production-readiness it hasn't earned will destroy
credibility with any serious security reviewer.

---

## Scope & ethics

For **authorized** security testing only. The dynamic stage executes a copy of the target application and sends it attack traffic; only run it against code you own or are permitted to test. Findings labelled CONFIRMED were reproduced live; STATIC_FINDINGs are heuristics requiring review.
