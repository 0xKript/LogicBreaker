"""
SARIF Report Generator  --   Enterprise
==========================================

Generates SARIF (Static Analysis Results Interchange Format) 1.0 output,
the OASIS standard for static analysis results.

SARIF is REQUIRED for integration with:
  - GitHub Code Scanning (PR reviews)
  - Azure DevOps pipelines
  - SonarQube
  - VS Code (SARIF Viewer extension)
  - Jenkins / GitLab CI gates

Without SARIF, the tool cannot integrate with modern CI/CD ecosystems.

Spec: https://docs.oasis-open.org/sarif/sarif/1.0/sarif-1.0.html
"""

from __future__ import annotations

import json
from typing import List
from datetime import datetime, timezone


# SARIF severity levels
SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}

# SARIF security severity values (0-10 scale, 10 = most severe)
SEVERITY_TO_SECURITY_SEVERITY = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 6.0,
    "LOW": 3.0,
    "INFO": 1.0,
}


def generate_sarif(findings: List[dict], tool_name: str = "LogicBreaker AI",
                   tool_version: str = "4.0.0",
                   information_uri: str = "https://logicbreaker.ai") -> dict:
    """Generate a SARIF 2.1.0 report from a list of findings.

    Each finding dict should have:
        - cwe (e.g. "CWE-89")
        - name (e.g. "SQL Injection")
        - severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
        - confidence (0.0-1.0)
        - file (path)
        - line (int)
        - snippet (the vulnerable code)
        - why (explanation)
        - fix (remediation)
        - sources (list of layer names: matcher/taint/ai)
        - consensus_count (int)
        - exploit_proven (bool)
        - fixed (bool)
        - compliance (dict: {owasp: [...], pci_dss: [...], ...})
    """
    # build rules (one per unique CWE)
    rules = []
    rule_index = {}
    for f in findings:
        cwe = (f.get("cwe") or "").upper()
        if not cwe or cwe in rule_index:
            continue
        rule_id = cwe
        rule_index[cwe] = len(rules)
        rules.append({
            "id": rule_id,
            "name": f.get("name", cwe),
            "shortDescription": {
                "text": f.get("name", cwe),
            },
            "fullDescription": {
                "text": f.get("why", "") or f.get("name", cwe),
            },
            "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html",
            "defaultConfiguration": {
                "level": SEVERITY_TO_LEVEL.get(f.get("severity", "MEDIUM"), "warning"),
            },
            "properties": {
                "tags": ["security", cwe.lower()],
                "precision": "high" if f.get("consensus_count", 0) >= 2 else "medium",
            },
        })

    # build results (one per finding)
    results = []
    for f in findings:
        cwe = (f.get("cwe") or "").upper()
        rule_idx = rule_index.get(cwe, 0)
        level = SEVERITY_TO_LEVEL.get(f.get("severity", "MEDIUM"), "warning")

        # build the message
        msg_parts = [f.get("name", cwe)]
        if f.get("why"):
            msg_parts.append(f.get("why"))
        if f.get("consensus_count", 0) >= 2:
            msg_parts.append(f"[cross-validated by {f['consensus_count']} layers]")
        if f.get("exploit_proven"):
            msg_parts.append("[exploit proven by execution]")

        # build the location
        location = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": f.get("file", "unknown"),
                },
                "region": {
                    "startLine": int(f.get("line", 1) or 1),
                },
            },
        }
        if f.get("snippet"):
            location["physicalLocation"]["region"]["snippet"] = {
                "text": f.get("snippet"),
            }

        # build fixes (if a fix was applied)
        fixes = []
        if f.get("fixed") and f.get("fix"):
            fixes.append({
                "description": {
                    "text": f.get("fix", ""),
                },
            })

        # build properties
        properties = {
            "confidence": round(float(f.get("confidence", 0.5)), 3),
            "severity": f.get("severity", "MEDIUM"),
            "sources": f.get("sources", []),
            "consensus_count": f.get("consensus_count", 1),
            "exploit_proven": bool(f.get("exploit_proven", False)),
            "fixed": bool(f.get("fixed", False)),
        }
        if f.get("compliance"):
            properties["compliance"] = f["compliance"]

        result = {
            "ruleId": cwe or "CWE-20",
            "ruleIndex": rule_idx,
            "level": level,
            "message": {
                "text": " | ".join(msg_parts),
            },
            "locations": [location],
            "properties": properties,
        }
        if fixes:
            result["fixes"] = fixes

        # security-severity property (for GitHub Code Scanning UI)
        sev_score = SEVERITY_TO_SECURITY_SEVERITY.get(f.get("severity", "MEDIUM"), 6.0)
        properties["security-severity"] = sev_score

        results.append(result)

    # build the SARIF document
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": information_uri,
                    "rules": rules,
                    "properties": {
                        "generatedAt": datetime.now(timezone.utc).isoformat(),
                    },
                },
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(timezone.utc).isoformat(),
            }],
        }],
    }
    return sarif


def write_sarif(findings: List[dict], output_path: str,
                tool_name: str = "LogicBreaker AI",
                tool_version: str = "4.0.0") -> str:
    """Generate SARIF and write it to a file. Returns the path."""
    sarif = generate_sarif(findings, tool_name=tool_name,
                           tool_version=tool_version)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)
    return output_path


def validate_sarif(sarif: dict) -> bool:
    """Basic SARIF schema validation (does not replace full OASIS validation
    but catches obvious structural errors)."""
    if not isinstance(sarif, dict):
        return False
    if sarif.get("version") != "2.1.0":
        return False
    if "$schema" not in sarif:
        return False
    runs = sarif.get("runs")
    if not isinstance(runs, list) or not runs:
        return False
    for run in runs:
        if "tool" not in run or "results" not in run:
            return False
        if "driver" not in run["tool"]:
            return False
    return True
