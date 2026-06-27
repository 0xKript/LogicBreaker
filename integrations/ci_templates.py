"""
CI/CD integration templates
==========================

Generates ready-to-commit pipeline configs that run LogicBreaker AI as a
security gate on every push / merge request. The tool exits non-zero when
CRITICAL or HIGH findings exist, so the pipeline fails the build (configurable).

  * GitHub Actions  -> .github/workflows/logicbreaker.yml
  * GitLab CI       -> .gitlab-ci.yml (a job snippet)

Both upload the HTML/PDF report as an artifact.
"""

import os


GITHUB_ACTIONS = """\
name: LogicBreaker AI Security Scan

on:
  push:
    branches: [ main, master, develop ]
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install LogicBreaker AI
        run: |
          pip install -r logicbreaker/requirements.txt

      - name: Run scan (fast mode, fails on HIGH/CRITICAL)
        run: |
          python logicbreaker/main.py \\
            --target . \\
            --fast \\
            --non-interactive \\
            --out lb_report \\
            --json lb_report/findings.json
        # To enable LLM triage, add: --provider groq --api-key ${{ secrets.GROQ_API_KEY }}

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@
        with:
          name: logicbreaker-report
          path: lb_report/
"""

GITLAB_CI = """\
# Add this job to your .gitlab-ci.yml
logicbreaker_security_scan:
  image: python:3.12
  stage: test
  script:
    - pip install -r logicbreaker/requirements.txt
    - python logicbreaker/main.py --target . --fast --non-interactive --out lb_report --json lb_report/findings.json
    # For LLM triage: --provider groq --api-key "$GROQ_API_KEY"
  artifacts:
    when: always
    paths:
      - lb_report/
    expire_in: 30 days
  # allow_failure: false  # fail the pipeline on HIGH/CRITICAL findings
"""

PRE_COMMIT = """\
# .pre-commit-config.yaml entry
-   repo: local
    hooks:
    -   id: logicbreaker
        name: LogicBreaker AI security scan
        entry: python logicbreaker/main.py --target . --fast --non-interactive --no-patch --out lb_report
        language: system
        pass_filenames: false
"""


def write_all(out_dir):
    """Write all CI templates under out_dir. Returns the written paths."""
    written = {}

    gh_dir = os.path.join(out_dir, ".github", "workflows")
    os.makedirs(gh_dir, exist_ok=True)
    gh_path = os.path.join(gh_dir, "logicbreaker.yml")
    with open(gh_path, "w", encoding="utf-8") as f:
        f.write(GITHUB_ACTIONS)
    written["github_actions"] = gh_path

    gl_path = os.path.join(out_dir, "gitlab-ci.logicbreaker.yml")
    with open(gl_path, "w", encoding="utf-8") as f:
        f.write(GITLAB_CI)
    written["gitlab_ci"] = gl_path

    pc_path = os.path.join(out_dir, "pre-commit.logicbreaker.yaml")
    with open(pc_path, "w", encoding="utf-8") as f:
        f.write(PRE_COMMIT)
    written["pre_commit"] = pc_path

    return written
