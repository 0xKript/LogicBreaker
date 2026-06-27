# Independent Security Review — Checklist & Template

> **Important:** This document is a *template* for an **external, independent**
> security team to complete. It is intentionally **not** filled in, because a
> meaningful security review cannot be written by the tool's author or by the
> tool itself — its value comes precisely from being independent. Hand this to
> a qualified third-party reviewer (internal security team, external auditor,
> or a CERT/accreditation body).

## 0. Reviewer & scope
- Reviewing organization / individual: ____________________
- Independence statement (no involvement in development): ____________________
- Version / commit reviewed: ____________________
- Date(s) of review: ____________________

## 1. Tool security (the scanner itself)
- [ ] The scanner does not execute untrusted target code outside the sandbox
- [ ] Sandbox isolation is adequate (process, filesystem, network egress)
- [ ] Temporary copies are always cleaned up, even on crash
- [ ] No secrets (API keys) are written to disk or logs
- [ ] Dependency supply chain reviewed (pinned versions, no known CVEs)
- [ ] The tool itself was scanned for vulnerabilities (SAST/DAST)
- [ ] Resource limits prevent denial-of-service on large/hostile inputs

## 2. Detection quality (measured, not claimed)
- [ ] Precision measured on ≥ N real-world projects: __________ %
- [ ] Recall measured against known-vulnerable corpora: __________ %
- [ ] False-positive rate documented per language and per vuln class
- [ ] Known false-negative classes documented
- [ ] Results reproduced independently by the reviewer

## 3. Live-exploitation safety
- [ ] Dynamic testing only runs against authorized targets
- [ ] Attack traffic is contained to the sandbox (no outbound to real systems)
- [ ] Destructive probes are clearly bounded and reversible
- [ ] Verified-fix re-testing cannot corrupt the user's real source

## 4. Operational / deployment
- [ ] Logging and audit trail sufficient for an enterprise/gov environment
- [ ] Access control / multi-user considerations (if deployed as a service)
- [ ] Data handling & retention policy for scanned code and reports
- [ ] Failure modes are safe (a crash never marks vulnerable code as clean silently)

## 5. Compliance / accreditation (jurisdiction-specific)
- [ ] Meets the relevant government/industry security framework: ____________
- [ ] Required certifications obtained: ____________
- [ ] Legal/liability coverage in place for production use: ____________

## 6. Reviewer conclusion
- Overall risk rating: ____________________
- Approved for: [ ] research / demo  [ ] internal pilot  [ ] production
- Conditions / required remediations before production:
  ____________________________________________________________________

Reviewer signature: ____________________   Date: ____________
