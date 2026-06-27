<div align="center">

# 🛡️ LogicBreaker

### AI-Powered Business-Logic Vulnerability Hunter, Live Exploiter & Auto-Patcher

**Detect → Exploit → Fix → Re-Attack**

A multi-layered security scanner that combines a deterministic rule engine, AST-based taint analysis, and LLM-driven deep detection to find, prove, and automatically fix vulnerabilities in source code.

**100% Precision · 99.2% Recall · 0 False Positives** *(measured on 242-case benchmark)*

</div>

---

## 📜 The Philosophy

Most "AI security" tools stop at an opinion: they ask a model whether code looks vulnerable. LogicBreaker goes further.

The core design follows a **"Suspect vs. Police"** model:

| Role | Who | Job |
|---|---|---|
| 🔴 **The Suspect** | The AI (LLM) | Discovers vulnerabilities and proposes fixes — creative but not trustworthy on its own |
| 🔵 **The Police** | Deterministic Engine | Verifies every claim, rejects lies, and proves by execution — trustworthy but limited to known patterns |

By combining both, LogicBreaker achieves the AI's coverage with the determinism's precision. The AI finds what the rules miss; the rules verify what the AI claims. Neither trusts the other blindly.

**The golden rule:** *Trust nothing the AI says — every claim and every fix is verified by deterministic code before it reaches the report.*

---

## ✨ What Makes It Different

| Capability | LogicBreaker |
|---|---|
| Detects business-logic flaws (race conditions, IDOR, price abuse, broken auth) | ✅ |
| **Proves** them with live exploitation against a running sandbox copy | ✅ |
| **Auto-patches** and **re-verifies** by re-attacking the fixed code | ✅ |
| Multi-layer detection: Rule Engine + Taint Analysis + AI (3-pass consensus) | ✅ |
| Anti-hallucination: self-critique + strict anchor verification | ✅ |
| Mitigation Recognition: no false positives on already-patched code | ✅ |
| Exploit Chain Detection: links multiple vulns into critical attack scenarios | ✅ |
| Enterprise reports: OWASP / PCI-DSS / NIST / ISO 27001 / SARIF / Audit Trail | ✅ |
| Works fully offline (no API key required) | ✅ |
| 15 LLM providers supported | ✅ |
| 25+ programming languages | ✅ |
| GitHub PR automation + CI/CD gates | ✅ |
| **Measured accuracy** (precision/recall benchmark) | ✅ |

---

## 🚀 Installation

```bash
git clone https://github.com/0xKript/LogicBreaker.git
cd LogicBreaker
pip install -r requirements.txt
```

**Requirements:**
- Python 3.10+ (including 3.12 / 3.13 / 3.14)
- `pip install -r requirements.txt` installs tree-sitter grammars, Flask, rich, reportlab, libcst, etc.

> On Windows, if `pip` isn't recognized, use `python -m pip` (or `py -m pip`).

---

## 🎯 Scan Modes (4 Modes)

Run `python main.py` interactively to choose a mode, or use flags for CI/CD.

### 1️⃣ Fast — Rule Engine Only
```bash
python main.py --target ./my_app --fast --html report.html
```
- ✅ Fast, free, fully offline
- ✅ Catches 30+ known vulnerability classes
- ❌ Cannot detect complex logic flaws the AI would catch

### 2️⃣ AI + API — Deep AI Analysis
```bash
python main.py --target ./my_app --provider groq --api-key gsk_XXX
```
- ✅ Most thorough — AI reads every file
- ✅ Detects any vulnerability type from understanding
- ❌ Slower (3-pass consensus + self-critique)

### 3️⃣ Hybrid — Rule Engine + AI (Recommended)
```bash
python main.py --target ./my_app --provider groq --api-key gsk_XXX --fix
```
- ✅ Best coverage and precision
- ✅ Rule engine catches known patterns fast; AI fills the gaps
- ✅ Cross-validation: both layers must agree for high confidence
- ✅ Mitigation Recognition prevents false positives on patched code

### 4️⃣ Dynamic — Live Exploitation
```bash
python main.py  # choose mode 4 interactively
```
- ✅ Everything in Hybrid **plus** launches your app in a sandbox
- ✅ Fires real HTTP attacks (SQLi, SSRF, Path Traversal, SSTI, XSS, RCE)
- ✅ Confirms vulnerabilities by execution — the strongest possible proof
- ✅ Re-attacks after fixing to prove the fix works

---

## 🧠 Supported LLM Providers (15)

| # | Provider | Key Prefix | Env Var |
|---|---|---|---|
| 1 | Anthropic Claude | `sk-ant-` | `ANTHROPIC_API_KEY` |
| 2 | OpenAI | `sk-` | `OPENAI_API_KEY` |
| 3 | Google Gemini | `AIza` | `GEMINI_API_KEY` |
| 4 | Groq *(Fastest)* | `gsk_` | `GROQ_API_KEY` |
| 5 | Mistral AI | varied | `MISTRAL_API_KEY` |
| 6 | DeepSeek | `sk-` | `DEEPSEEK_API_KEY` |
| 7 | Together AI | varied | `TOGETHER_API_KEY` |
| 8 | OpenRouter | `sk-or-` | `OPENROUTER_API_KEY` |
| 9 | xAI Grok | `xai-` | `XAI_API_KEY` |
| 10 | Cohere | varied | `COHERE_API_KEY` |
| 11 | Perplexity | `pplx-` | `PERPLEXITY_API_KEY` |
| 12 | Fireworks AI | `fw_` | `FIREWORKS_API_KEY` |
| 13 | Cerebras | `csk-` | `CEREBRAS_API_KEY` |
| 14 | SambaNova | varied | `SAMBANOVA_API_KEY` |
| 15 | Nebius | varied | `NEBIUS_API_KEY` |

API keys are verified with a **live test request** before scanning begins — no silent acceptance of invalid keys.

---

## 🛡️ Supported Vulnerabilities (32+ Detectors)

### Injection Family
| CWE | Vulnerability | Status |
|---|---|---|
| CWE-89 | SQL Injection | ✅ Detect + Fix + Exploit |
| CWE-78 | OS Command Injection | ✅ Detect + Fix + Exploit |
| CWE-94 | Code Injection (eval/exec) | ✅ Detect + Fix + Exploit |
| CWE-79 | Cross-Site Scripting (XSS) | ✅ Detect + Fix + Exploit |
| CWE-1336 | Server-Side Template Injection (SSTI) | ✅ Detect + Fix + Exploit |
| CWE-502 | Insecure Deserialization | ✅ Detect + Fix + Exploit |
| CWE-611 | XML External Entity (XXE) | ✅ Detect + Fix |
| CWE-918 | Server-Side Request Forgery (SSRF) | ✅ Detect + Fix + Exploit |

### Access Control & Auth
| CWE | Vulnerability | Status |
|---|---|---|
| CWE-22 | Path Traversal | ✅ Detect + Fix + Exploit |
| CWE-639 | Insecure Direct Object Reference (IDOR) | ✅ Detect + Fix + Exploit |
| CWE-602 | Broken Authorization | ✅ Detect + Fix |
| CWE-287 | Broken Authentication | ✅ Detect + Fix |
| CWE-306 | Missing Authentication | ✅ Detect + Fix |
| CWE-915 | Mass Assignment | ✅ Detect + Fix |
| CWE-601 | Open Redirect | ✅ Detect + Fix + Exploit |
| CWE-352 | CSRF Protection Disabled | ✅ Detect + Fix |
| CWE-307 | Missing Rate Limiting | ✅ Detect + Fix |

### Cryptography & Config
| CWE | Vulnerability | Status |
|---|---|---|
| CWE-327 | Weak Cryptography (MD5/SHA1) | ✅ Detect + Fix |
| CWE-330 | Insecure Randomness | ✅ Detect + Fix |
| CWE-798 | Hardcoded Secret/Credential | ✅ Detect + Fix |
| CWE-489 | Debug Mode Enabled | ✅ Detect + Fix |
| CWE-942 | Permissive CORS | ✅ Detect + Fix |
| CWE-347 | JWT Verification Weakness | ✅ Detect + Fix |
| CWE-295 | Disabled TLS Verification | ✅ Detect + Fix |
| CWE-377 | Insecure Temporary File | ✅ Detect + Fix |
| CWE-1004 | Insecure Cookie Flags | ✅ Detect + Fix |
| CWE-200 | Sensitive Information Exposure | ✅ Detect + Fix |
| CWE-732 | Overly Permissive File Permissions | ✅ Detect + Fix |

### Business Logic
| CWE | Vulnerability | Status |
|---|---|---|
| CWE-367 | Race Condition (TOCTOU) | ✅ Detect + Fix + Exploit |
| CWE-840 | Price/Quantity Manipulation | ✅ Detect + Fix |
| CWE-840 | Negative/Zero Quantity | ✅ Detect + Fix |

> **Note:** The AI layer can detect ANY vulnerability type beyond this list — these are just the deterministic matchers.

---

## 🌍 Supported Languages (25+)

### Deep Support (AST-based taint tracking + specialized matchers)
| Language | Frameworks Covered |
|---|---|
| **Python** | Flask, FastAPI, Django, raw |
| **JavaScript** | Express, Node.js, raw http |
| **TypeScript** | Express TS, raw |
| **TSX** | React |
| **PHP** | WordPress, Laravel, raw |
| **Java** | Spring |
| **Go** | net/http, Gin |
| **Ruby** | Sinatra, Rails |
| **C#** | ASP.NET |

### Parsed Support (Generic matchers + tree-sitter AST)
C, C++, Rust, Kotlin, Scala, Bash, Lua, SQL, HTML, CSS, JSON, YAML, and more.

Run `python main.py --list-languages` to see which grammars are installed.

---

## 💻 Usage & Commands

### Interactive Mode (Recommended)
```bash
python main.py
```
You will be prompted to:
1. Choose a scan mode (Fast / AI+API / Hybrid / Dynamic)
2. Choose an API provider (if AI mode)
3. Enter your API key (verified live)
4. Enter the target path
5. Confirm whether to apply fixes

### Non-Interactive / CI/CD

**Fast Scan (Offline, Free)**
```bash
python main.py --target ./my_app --fast --html report.html --non-interactive
```

**Hybrid Scan with AI + Auto-Fix**
```bash
python main.py --target ./my_app \
  --provider groq --api-key gsk_XXX \
  --fix --compliance all --sarif results.sarif --non-interactive
```

**Dynamic Scan (Live Exploitation)**
```bash
python main.py --target ./my_app \
  --provider groq --api-key gsk_XXX \
  --fix --html report.html --non-interactive
```
*(Dynamic mode is selected interactively as mode 4)*

### All CLI Flags

| Flag | Description |
|---|---|
| `-t, --target` | Path to the codebase to scan |
| `--fast` | Fast scan: no LLM (fully local, offline) |
| `--provider` | LLM provider id (claude, openai, gemini, groq, ...) |
| `--api-key` | API key for the chosen provider |
| `--model` | Override the provider's default model |
| `--fix` | Apply verified fixes to source files (originals backed up) |
| `--interactive-fix` | Ask yes/no before fixing each vulnerability |
| `--no-dynamic` | Skip live exploitation stage |
| `--no-patch` | Skip auto-patching stage |
| `--no-ai-detect` | Disable AI detection (rule engine only) |
| `--compliance` | Generate compliance report (OWASP, PCI-DSS, NIST, ISO, all) |
| `--sarif` | Write SARIF 2.1.0 output (for GitHub Code Scanning / CI) |
| `--audit-trail` | Write audit trail JSON (for SOC 2 / ISO 27001) |
| `--n-passes` | AI consensus passes (default: 3) |
| `--max-workers` | Parallel workers for batch scanning (0 = auto) |
| `--priority-files` | Comma-separated keywords for high-priority files (auth,payment,admin) |
| `--offline` | Force offline mode (rule engine only) |
| `--no-cache` | Disable LLM response cache |
| `--feedback` | Load false-positive feedback file |
| `--target-url` | Scan a LIVE WordPress site with WPScan |
| `--wpscan-token` | WPScan API token |
| `--export-patches` | Write patches as .patch files + PR body |
| `--open-pr` | Open a GitHub PR with the fixes (needs GITHUB_TOKEN) |
| `--init-ci` | Write GitHub Actions / GitLab CI / pre-commit templates |
| `--list-matchers` | List all vulnerability detectors and exit |
| `--list-languages` | List all supported languages and exit |
| `--list-runtimes` | Show installed language runtimes for live exploitation |
| `--non-interactive` | Never prompt; use flags only |
| `--deep` | Enable LLM safety net for suspicious-but-unflagged code |
| `--skip-key-check` | Skip live API-key verification (not recommended) |
| `--no-semgrep` | Skip complementary Semgrep scan |
| `--no-enrich` | Skip CVE/CWE enrichment |
| `--concurrency` | Concurrent requests for race probes (default: 20) |
| `--max-file-bytes` | Per-file size cap (default: 1,500,000) |
| `--max-files` | Limit number of files scanned |
| `--min-confidence` | Hide findings below this confidence (0.0-1.0) |
| `-o, --out` | Output directory (default: logicbreaker_report) |
| `--html` | HTML report filename |
| `--pdf` | PDF report filename |
| `--json` | Write findings as JSON |

### Restore Original Files (After Auto-Fix)
```bash
python -m core.backup_manager restore "./app/.logicbreaker_backups/<timestamp>"
```

---

## 📊 Enterprise & Compliance Reports

LogicBreaker generates reports suitable for government and enterprise audits:

### Compliance Mapping
- **OWASP Top 10 (2021)** — maps each finding to OWASP categories
- **PCI-DSS v4.0** — maps to Payment Card Industry requirements
- **NIST 800-53 Rev 5** — maps to NIST control families
- **ISO 27001** — maps to ISO control objectives

### Output Formats
- **HTML Report** — clean, readable, human-friendly
- **PDF Report** — printable for management
- **JSON** — for automation and CI/CD
- **SARIF 2.1.0** — OASIS standard for GitHub Code Scanning, SonarQube, VS Code
- **Audit Trail** — JSON log of every decision (detect, investigate, exploit, fix, re-attack) with timestamps — for SOC 2 / ISO 27001 compliance
- **Exploit Chains** — links multiple vulnerabilities into critical attack scenarios (e.g., Path Traversal + RCE = Critical)
- **Patch Files** — unified diffs for review or Git PR

---

## 🔧 How It Works (The Pipeline)

```
Source Code
     │
     ▼
┌─────────────────────────────────────────────┐
│ 1. Rule Engine (matchers)                    │
│    Fast regex-based detection of 30+ CWEs   │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│ 2. Taint Engine (AST)                        │
│    Interprocedural data-flow tracking       │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│ 3. AI Detector (3-pass consensus)            │
│    LLM reads code + self-critique           │
│    Finds ANY type of vulnerability          │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│ 4. Merge Layer                               │
│    De-duplicate + cross-validate + rank     │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│ 5. Investigator (deterministic)              │
│    Anchor + sink verification               │
│    Rejects hallucinations                   │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│ 6. Exploit Prover (execution)                │
│    Fires real attacks in sandbox            │
│    15+ vulnerability classes                │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│ 7. AI Surgeon (fix)                          │
│    Proposes root-cause fix                  │
│    Closes ALL bypasses                      │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│ 8. Fix Prover (execution)                    │
│    Patched code must parse + load + work    │
│    Exploit must no longer fire              │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│ 9. Re-Attacker (final verification)          │
│    Re-launches original exploit             │
│    Must FAIL on patched code                │
└─────────────────────────────────────────────┘
     │
     ▼
  Reports + Patches
```

---

## 🛡️ Anti-Hallucination Architecture

The AI is powerful but can hallucinate. LogicBreaker has **5 walls** against hallucination:

1. **3-Pass Consensus** — the AI scans code 3 times; findings in all 3 passes get +15 confidence
2. **Self-Critique** — the AI reviews its own findings and retracts those it cannot defend
3. **Strict Anchor** — the AI's claimed `snippet` must appear verbatim in the file (>= 70% match)
4. **Investigator** — deterministic code verifies the sink is on the cited line and the source is in the same function
5. **Mitigation Recognition** — if the code already contains a fix pattern (e.g., `ast.literal_eval`), the finding is suppressed

---

## 📁 Project Structure

```
logicbreaker/
├── main.py                  # CLI entry point + all flags
├── agents/                  # AI components
│   ├── ai_detector.py       #   🔴 AI Detector (3-pass + self-critique)
│   ├── ai_surgeon.py        #   🔴 AI Surgeon (fix proposer)
│   ├── ai_pipeline.py       #   🎯 Orchestrator
│   ├── llm_client.py        #   15 providers + key verification + caching
│   ├── healer.py            #   Deterministic fixer
│   └── code_fixer.py        #   In-file code transforms
├── cli/                     # Interactive UI
│   ├── ui.py                #   Rich banner, tables, colors
│   └── interactive.py       #   Scan mode + provider selection
├── core/                    # Engine & verifiers
│   ├── scan_engine.py       #   Rule engine + matchers runner
│   ├── taint_engine.py      #   AST-based taint tracking
│   ├── case_validator.py    #   🔵 Investigator (anchor verification)
│   ├── exploit_prover.py    #   🟢 Exploit Prover (execution)
│   ├── fix_prover.py        #   🟢 Fix Prover (execution)
│   ├── re_attacker.py       #   🟢 Re-Attacker (final verification)
│   ├── orchestrator.py      #   Pipeline coordinator
│   ├── findings_merger.py   #   Cross-validation + dedup
│   ├── audit_trail.py       #   Decision logging
│   └── ...
├── matchers/                # 32+ vulnerability detectors
├── reporting/               # HTML, PDF, SARIF, Compliance
├── scanners/                # File discovery, route extraction
├── sandbox/                 # Ephemeral app execution
├── languages/               # Tree-sitter parser (25+ languages)
├── integrations/            # GitHub PR, CI/CD templates
├── tests/                   # Unit tests & E2E verification
├── benchmark/               # 242-case accuracy corpus
└── test_corpus/             # Sample vulnerable & safe files
```

---

## 🧪 Testing & Benchmark

```bash
# Run the accuracy benchmark (242 cases)
python benchmark/run_benchmark_v2.py

# Run anti-hallucination unit tests
python tests/test_anti_hallucination.py

# Run end-to-end fix verification
python tests/test_e2e_fix.py

# Run performance benchmark
python tests/test_performance.py
```

**Benchmark Results:**
- **Precision:** 100.0% (0 false positives)
- **Recall:** 99.2% (122/123 vulnerable files detected)
- **F1 Score:** 99.6%

---

## ⚙️ Environment Variables

| Variable | Description |
|---|---|
| `LB_AI_DEBUG=1` | Print verbose per-file diagnostics to stderr |
| `LB_AI_FILE_BUDGET=0` | Max files for AI scanning (0 = unlimited) |
| `LB_NO_LLM_CACHE=1` | Disable LLM response cache |
| `LB_CACHE_DIR=/path` | Override cache directory |
| `LB_OFFLINE=1` | Force offline mode |
| `GITHUB_TOKEN` | For `--open-pr` |
| `WPSCAN_API_TOKEN` | For WordPress live scanning |

---

## 🔌 Adding Your Own Detector (Plugin System)

Drop a file in `matchers/plugins/` exposing a `MATCHERS` list of `BaseMatcher` subclasses. It's auto-discovered at startup — **no engine changes**. See `matchers/plugins/example_ssrf.py`.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## ⚖️ Scope & Ethics

For **authorized** security testing only. The dynamic stage executes a copy of the target application and sends it attack traffic; only run it against code you own or are permitted to test. Findings labelled `CONFIRMED` were reproduced live; `STATIC_FINDING`s are heuristics requiring review.

---

<div align="center">

**Built for quality, precision, and enterprise-grade security.**

</div>
