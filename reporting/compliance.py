"""
Compliance Mapper  --   Enterprise
=====================================

Maps each finding to compliance frameworks:
  - OWASP Top 10 (2021)
  - PCI-DSS v4.0
  - NIST 800-53 Rev 5
  - ISO 27001
  - CWE Top 25

This is REQUIRED for government/enterprise audits. Without compliance
mapping, the tool cannot pass external security reviews.

Each CWE maps to one or more requirements in each framework. The mapper
produces a per-framework report showing which requirements PASS/FAIL.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


# ============================================================================
# OWASP Top 10 (2021) -- maps each OWASP category to CWEs
# ============================================================================

OWASP_TOP_10_2021 = {
    "A01: Broken Access Control": {
        "cwes": ["CWE-22", "CWE-78", "CWE-287", "CWE-306", "CWE-602",
                 "CWE-639", "CWE-862", "CWE-863", "CWE-913", "CWE-915"],
        "description": "Restrictions on what authenticated users are allowed to do are not properly enforced.",
    },
    "A02: Cryptographic Failures": {
        "cwes": ["CWE-327", "CWE-328", "CWE-329", "CWE-347", "CWE-798",
                 "CWE-916"],
        "description": "Failures related to cryptography that often lead to exposure of sensitive data.",
    },
    "A03: Injection": {
        "cwes": ["CWE-79", "CWE-89", "CWE-90", "CWE-94", "CWE-113",
                 "CWE-643", "CWE-943", "CWE-1336"],
        "description": "User-supplied data is not validated, filtered, or sanitized by the application.",
    },
    "A04: Insecure Design": {
        "cwes": ["CWE-209", "CWE-256", "CWE-501", "CWE-522", "CWE-787"],
        "description": "Missing or ineffective control design.",
    },
    "A05: Security Misconfiguration": {
        "cwes": ["CWE-16", "CWE-489", "CWE-942", "CWE-1188", "CWE-1390"],
        "description": "Missing or incorrect hardening of the application or its environment.",
    },
    "A06: Vulnerable and Outdated Components": {
        "cwes": ["CWE-937", "CWE-1035"],
        "description": "Using components with known vulnerabilities.",
    },
    "A07: Identification and Authentication Failures": {
        "cwes": ["CWE-287", "CWE-290", "CWE-294", "CWE-307", "CWE-308",
                 "CWE-346", "CWE-384", "CWE-798"],
        "description": "Authentication-related failures.",
    },
    "A08: Software and Data Integrity Failures": {
        "cwes": ["CWE-502", "CWE-829", "CWE-494"],
        "description": "Code and data integrity verification failures.",
    },
    "A09: Security Logging and Monitoring Failures": {
        "cwes": ["CWE-778", "CWE-117", "CWE-223", "CWE-532"],
        "description": "Failures in logging and monitoring.",
    },
    "A10: Server-Side Request Forgery (SSRF)": {
        "cwes": ["CWE-918", "CWE-921"],
        "description": "SSRF occurs whenever a web application fetches a remote resource without validating the user-supplied URL.",
    },
}


# ============================================================================
# PCI-DSS v4.0 -- maps requirements to CWEs
# ============================================================================

PCI_DSS_V4 = {
    "6.5.1: Injection flaws": {
        "cwes": ["CWE-89", "CWE-78", "CWE-90", "CWE-94", "CWE-943",
                 "CWE-643", "CWE-113"],
        "description": "Injection flaws, such as SQL injection, command injection, LDAP injection.",
    },
    "6.5.2: Broken authentication": {
        "cwes": ["CWE-287", "CWE-290", "CWE-307", "CWE-798"],
        "description": "Broken authentication and session management.",
    },
    "6.5.3: Sensitive data exposure": {
        "cwes": ["CWE-327", "CWE-328", "CWE-347", "CWE-200", "CWE-209"],
        "description": "Sensitive data exposure (cryptographic failures).",
    },
    "6.5.4: XXE": {
        "cwes": ["CWE-611"],
        "description": "XML External Entity (XXE) processing.",
    },
    "6.5.5: Broken access control": {
        "cwes": ["CWE-22", "CWE-602", "CWE-639", "CWE-862", "CWE-863"],
        "description": "Broken access control.",
    },
    "6.5.6: Security misconfiguration": {
        "cwes": ["CWE-16", "CWE-489", "CWE-942"],
        "description": "Security misconfiguration.",
    },
    "6.5.7: XSS": {
        "cwes": ["CWE-79"],
        "description": "Cross-site scripting (XSS).",
    },
    "6.5.8: Insecure deserialization": {
        "cwes": ["CWE-502"],
        "description": "Insecure deserialization.",
    },
    "6.5.9: Known vulnerable components": {
        "cwes": ["CWE-937", "CWE-1035"],
        "description": "Using components with known vulnerabilities.",
    },
    "6.5.10: Insufficient logging": {
        "cwes": ["CWE-778", "CWE-223", "CWE-532"],
        "description": "Insufficient logging and monitoring.",
    },
    "6.5.11: SSRF": {
        "cwes": ["CWE-918"],
        "description": "Server-Side Request Forgery (SSRF).",
    },
}


# ============================================================================
# NIST 800-53 Rev 5 -- maps control families to CWEs
# ============================================================================

NIST_800_53_R5 = {
    "AC-3: Access Enforcement": {
        "cwes": ["CWE-22", "CWE-602", "CWE-639", "CWE-862", "CWE-863"],
        "description": "The system enforces approved authorizations for logical access to information and system resources.",
    },
    "AC-7: Unsuccessful Login Attempts": {
        "cwes": ["CWE-307"],
        "description": "Enforces a limit of consecutive invalid logon attempts by a user during a time period.",
    },
    "AU-2: Event Logging": {
        "cwes": ["CWE-778", "CWE-223", "CWE-532"],
        "description": "The system generates audit records for security-relevant events.",
    },
    "IA-2: Identification and Authentication": {
        "cwes": ["CWE-287", "CWE-290", "CWE-798"],
        "description": "The system uniquely identifies and authenticates users.",
    },
    "IA-5: Authenticator Management": {
        "cwes": ["CWE-798", "CWE-327", "CWE-347"],
        "description": "Authenticator management (passwords, keys, tokens).",
    },
    "SC-8: Transmission Confidentiality and Integrity": {
        "cwes": ["CWE-327", "CWE-329"],
        "description": "Protects the confidentiality and integrity of transmitted information.",
    },
    "SC-13: Cryptographic Protection": {
        "cwes": ["CWE-327", "CWE-328", "CWE-347"],
        "description": "Use of cryptographic mechanisms to protect information.",
    },
    "SI-10: Information Input Validation": {
        "cwes": ["CWE-79", "CWE-89", "CWE-78", "CWE-90", "CWE-94",
                 "CWE-918", "CWE-943", "CWE-611", "CWE-502", "CWE-113",
                 "CWE-643"],
        "description": "The system validates information input.",
    },
    "SI-15: Information Filtering": {
        "cwes": ["CWE-79", "CWE-89", "CWE-78", "CWE-918"],
        "description": "The system filters information to detect/remove malicious content.",
    },
}


# ============================================================================
# ISO 27001 -- maps control families to CWEs
# ============================================================================

ISO_27001 = {
    "A.9: Access Control": {
        "cwes": ["CWE-22", "CWE-287", "CWE-306", "CWE-602", "CWE-639",
                 "CWE-862", "CWE-863"],
        "description": "Access control objectives.",
    },
    "A.10: Cryptography": {
        "cwes": ["CWE-327", "CWE-328", "CWE-329", "CWE-347", "CWE-798"],
        "description": "Cryptographic controls.",
    },
    "A.12.6: Technical Vulnerability Management": {
        "cwes": ["CWE-937", "CWE-1035"],
        "description": "Technical vulnerability management.",
    },
    "A.14.2: Security in Development and Support": {
        "cwes": ["CWE-89", "CWE-78", "CWE-79", "CWE-502", "CWE-918",
                 "CWE-22", "CWE-489", "CWE-942"],
        "description": "Security in development and support processes.",
    },
}


# ============================================================================
# CWE Top 25 (2023) -- the most dangerous CWEs
# ============================================================================

CWE_TOP_25_2023 = {
    "CWE-787": "Out-of-bounds Write",
    "CWE-79": "Cross-site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-494": "Download of Code Without Integrity Check",
    "CWE-98": "PHP File Inclusion",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-287": "Improper Authentication",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-416": "Use After Free",
    "CWE-862": "Missing Authorization",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-918": "SSRF",
    "CWE-119": "Buffer Overflow (improper restriction of operations within bounds of a memory buffer)",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-125": "Out-of-bounds Read",
    "CWE-89": "SQL Injection",  # duplicate (kept for ranking)
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-352": "CSRF",
    "CWE-22": "Path Traversal",  # duplicate
    "CWE-276": "Incorrect Default Permissions",
    "CWE-918": "SSRF",  # duplicate
}


# ============================================================================
# Compliance Mapper
# ============================================================================

@dataclass
class ComplianceFinding:
    """A finding with its compliance mappings."""
    cwe: str
    name: str
    file: str
    line: int
    severity: str
    confidence: float

    # compliance mappings (filled by the mapper)
    owasp: List[str] = field(default_factory=list)
    pci_dss: List[str] = field(default_factory=list)
    nist: List[str] = field(default_factory=list)
    iso: List[str] = field(default_factory=list)
    is_cwe_top_25: bool = False


@dataclass
class ComplianceReport:
    """Per-framework compliance report."""
    framework: str
    requirements: list  # [{requirement, status, findings, description}]
    overall_status: str  # "PASS" | "FAIL"
    total_findings: int = 0


class ComplianceMapper:
    """Maps findings to compliance frameworks and produces reports."""

    def map_finding(self, cwe: str, name: str = "", file: str = "",
                    line: int = 0, severity: str = "MEDIUM",
                    confidence: float = 0.5) -> ComplianceFinding:
        """Map a single finding to compliance frameworks."""
        cwe = (cwe or "").upper()
        cf = ComplianceFinding(cwe=cwe, name=name, file=file, line=line,
                               severity=severity, confidence=confidence)

        # OWASP Top 10
        for cat, info in OWASP_TOP_10_2021.items():
            if cwe in info["cwes"]:
                cf.owasp.append(cat)

        # PCI-DSS
        for req, info in PCI_DSS_V4.items():
            if cwe in info["cwes"]:
                cf.pci_dss.append(req)

        # NIST 800-53
        for ctrl, info in NIST_800_53_R5.items():
            if cwe in info["cwes"]:
                cf.nist.append(ctrl)

        # ISO 27001
        for ctrl, info in ISO_27001.items():
            if cwe in info["cwes"]:
                cf.iso.append(ctrl)

        # CWE Top 25
        cf.is_cwe_top_25 = cwe in CWE_TOP_25_2023

        return cf

    def generate_report(self, findings: List[ComplianceFinding],
                        framework: str = "all") -> dict:
        """Generate compliance reports for each framework.

        Returns:
            {
                "owasp": ComplianceReport,
                "pci_dss": ComplianceReport,
                "nist": ComplianceReport,
                "iso": ComplianceReport,
            }
        """
        reports = {}
        if framework in ("all", "owasp"):
            reports["owasp"] = self._report_owasp(findings)
        if framework in ("all", "pci_dss"):
            reports["pci_dss"] = self._report_pci(findings)
        if framework in ("all", "nist"):
            reports["nist"] = self._report_nist(findings)
        if framework in ("all", "iso"):
            reports["iso"] = self._report_iso(findings)
        return reports

    def _report_owasp(self, findings: List[ComplianceFinding]) -> ComplianceReport:
        reqs = []
        for cat, info in OWASP_TOP_10_2021.items():
            matched = [f for f in findings if cat in f.owasp]
            reqs.append({
                "requirement": cat,
                "status": "FAIL" if matched else "PASS",
                "findings_count": len(matched),
                "findings": [{"cwe": f.cwe, "name": f.name, "file": f.file,
                              "line": f.line, "severity": f.severity}
                             for f in matched],
                "description": info["description"],
            })
        overall = "FAIL" if any(r["status"] == "FAIL" for r in reqs) else "PASS"
        return ComplianceReport(
            framework="OWASP Top 10 (2021)",
            requirements=reqs,
            overall_status=overall,
            total_findings=sum(r["findings_count"] for r in reqs))

    def _report_pci(self, findings: List[ComplianceFinding]) -> ComplianceReport:
        reqs = []
        for req, info in PCI_DSS_V4.items():
            matched = [f for f in findings if req in f.pci_dss]
            reqs.append({
                "requirement": req,
                "status": "FAIL" if matched else "PASS",
                "findings_count": len(matched),
                "findings": [{"cwe": f.cwe, "name": f.name, "file": f.file,
                              "line": f.line, "severity": f.severity}
                             for f in matched],
                "description": info["description"],
            })
        overall = "FAIL" if any(r["status"] == "FAIL" for r in reqs) else "PASS"
        return ComplianceReport(
            framework="PCI-DSS v4.0",
            requirements=reqs,
            overall_status=overall,
            total_findings=sum(r["findings_count"] for r in reqs))

    def _report_nist(self, findings: List[ComplianceFinding]) -> ComplianceReport:
        reqs = []
        for ctrl, info in NIST_800_53_R5.items():
            matched = [f for f in findings if ctrl in f.nist]
            reqs.append({
                "requirement": ctrl,
                "status": "FAIL" if matched else "PASS",
                "findings_count": len(matched),
                "findings": [{"cwe": f.cwe, "name": f.name, "file": f.file,
                              "line": f.line, "severity": f.severity}
                             for f in matched],
                "description": info["description"],
            })
        overall = "FAIL" if any(r["status"] == "FAIL" for r in reqs) else "PASS"
        return ComplianceReport(
            framework="NIST 800-53 Rev 5",
            requirements=reqs,
            overall_status=overall,
            total_findings=sum(r["findings_count"] for r in reqs))

    def _report_iso(self, findings: List[ComplianceFinding]) -> ComplianceReport:
        reqs = []
        for ctrl, info in ISO_27001.items():
            matched = [f for f in findings if ctrl in f.iso]
            reqs.append({
                "requirement": ctrl,
                "status": "FAIL" if matched else "PASS",
                "findings_count": len(matched),
                "findings": [{"cwe": f.cwe, "name": f.name, "file": f.file,
                              "line": f.line, "severity": f.severity}
                             for f in matched],
                "description": info["description"],
            })
        overall = "FAIL" if any(r["status"] == "FAIL" for r in reqs) else "PASS"
        return ComplianceReport(
            framework="ISO 27001",
            requirements=reqs,
            overall_status=overall,
            total_findings=sum(r["findings_count"] for r in reqs))

    def to_dict(self, report: ComplianceReport) -> dict:
        return {
            "framework": report.framework,
            "overall_status": report.overall_status,
            "total_findings": report.total_findings,
            "requirements": report.requirements,
        }
