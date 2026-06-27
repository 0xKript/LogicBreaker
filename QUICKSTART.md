# LogicBreaker AI — Quick Start

## Install
```bash
pip install -r requirements.txt
```

## Scan your code
Point it at any folder containing source code:
```bash
python main.py --target "C:\path\to\your\project" --fast --non-interactive --out my_report
```
It scans the tree, detects business-logic vulnerabilities across 21 languages,
and (where a runtime is available) launches the app to prove them with live
exploitation. Open `my_report/report.html` to see the results.

## Find → exploit → ask → fix → re-verify
```bash
# Ask yes/no before fixing each vulnerability; fixes are applied IN-FILE and the
# original is backed up first. A re-scan afterwards shows the issue CLOSED.
python main.py --target "C:\path\to\your\project" --fast --interactive-fix --fix --out my_report

# Apply all verified fixes without prompting (still backs up every original)
python main.py --target "C:\path\to\your\project" --fast --non-interactive --fix --out my_report

# Roll back every applied fix
python -m core.backup_manager restore "C:\path\to\your\project\.logicbreaker_backups\<timestamp>"
```

## See what's inside
```bash
python main.py --list-languages   # 21 supported languages
python main.py --list-matchers    # 21 vulnerability detectors
python main.py --list-runtimes    # which language runtimes are installed (for live exploitation)
```

## Measure accuracy (precision / recall)
```bash
python benchmark/run_benchmark.py
```
Runs a labelled corpus of vulnerable + safe files and reports precision, recall,
and false-positive rate. Add your own cases under `benchmark/cases/`.

## Pre-generated sample
Open `sample_report/report.html` or `sample_report/report.pdf` to see exactly
what a scan produces — no setup needed.
