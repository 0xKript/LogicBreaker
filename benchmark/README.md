# LogicBreaker AI — Accuracy Benchmark (200 cases)

A self-validating, adversarial correctness suite for the LogicBreaker AI scanner.
Every case is a **real file that is actually scanned** — nothing is mocked, so the
reported numbers are reproducible by re-running the scanner on this corpus.

## What it measures

| Bucket | Location | Pass condition |
|--------|----------|----------------|
| Vulnerable | `cases/vulnerable/` | scanner must report **≥ 1 finding** (true positive) |
| Safe (traps) | `cases/safe/` | scanner must report **0 findings** (true negative) |

A *safe* case is an adversarial **trap**: code engineered to *look* dangerous
(string-built SQL, a shell call, a deserialiser, a redirect) while being provably
safe (bound parameters, `escapeshellarg`/`shlex.quote`, `yaml.safe_load`, an
allow-list). Traps are where precision is won or lost.

## Current result

```
200 cases  (100 vulnerable + 100 safe)
Precision 100.0%   Recall 100.0%   F1 100.0%   False-Positive Rate 0.0%
```

- **31** distinct CWE classes on the vulnerable side
- **10** languages (Python, PHP, JavaScript, Java, Go, C, C++, C#, Kotlin, Rust)
- Difficulty tiers: `obvious`, `hidden` (interprocedural / multi-step),
  `adversarial` (the safe traps)
- **18** WordPress-plugin-style cases (WooCommerce, Elementor, WPForms, CF7, SEO,
  backup, membership, gallery, cache, importer plugins)

## How to run

```bash
# rich report: overall + per-CWE / per-language / per-difficulty / per-severity,
# and a loud list of any failing case
python3 benchmark/run_benchmark_v2.py

# minimal pass/fail gate
python3 benchmark/run_benchmark.py

# regenerate the metadata manifest after adding/removing cases
python3 benchmark/build_manifest.py
```

`run_benchmark_v2.py` exits non-zero if any vulnerable case is missed or any safe
case is flagged, so it can be wired straight into CI as a regression gate.

## Files

- `cases/vulnerable/*`, `cases/safe/*` — the corpus (one vuln/trap per file)
- `cases.json` — generated manifest (id, title, CWE, severity, language,
  difficulty) used for the per-category breakdowns
- `run_benchmark_v2.py` — enhanced self-validating runner
- `run_benchmark.py` — simple gate
- `build_manifest.py` — manifest generator

## Detector improvements validated by this suite

Building the suite surfaced (and the engine was hardened against) several real
gaps, every one kept **zero-false-positive** against both the safe traps here and
the real-world WordPress regression corpora:

- Django request sources (`request.GET/POST/body/FILES/...`)
- JavaScript NoSQL sinks (Mongo `findOne/updateOne/...`) — deliberately excluding
  bare `.find(` so it never collides with jQuery DOM traversal
- PHP LDAP sink (`ldap_search`) + `ldap_escape` sanitiser
- Robust call-chain callee extraction (so `db.collection("x").findOne(...)` is
  seen instead of stopping at `collection(`)
- Derived-variable taint propagation (a value built from a tainted value is
  tainted) with transitive **sanitiser provenance** (a cleanser applied on an
  earlier assignment line is honoured)
- Literal-only shell-metacharacter detection (a PHP `$var` sigil is no longer
  mistaken for a shell metacharacter)
- ORM-aware SQL (SQLAlchemy/Django `.filter/.filter_by/.exclude` are bound
  parameters, not raw SQL)
- Allow-list-aware open-redirect (membership in a constant set is a validation)
- Regex-whitelist / `isdigit` / `isalnum` validation guards for path traversal
- Quote/space-insensitive JWT verification checks
