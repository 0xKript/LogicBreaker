#!/usr/bin/env python3
"""Build/refresh benchmark/cases.json. Infers metadata for any case file that is
not already described, from its path + a keyword scan. New cases added by the
generator overwrite their own entries with precise metadata."""
import json, os, re

HERE = os.path.dirname(os.path.abspath(__file__))
DIRS = {"vulnerable": os.path.join(HERE, "cases", "vulnerable"),
        "safe": os.path.join(HERE, "cases", "safe")}
OUT = os.path.join(HERE, "cases.json")

EXT_LANG = {".php": "PHP", ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
            ".java": "Java", ".cs": "C#", ".kt": "Kotlin", ".rs": "Rust",
            ".c": "C", ".cpp": "C++", ".go": "Go", ".rb": "Ruby"}

# filename keyword -> (vuln class, cwe)
KW = [
    ("sqli", ("SQL Injection", "CWE-89")), ("sql_", ("SQL Injection", "CWE-89")),
    ("cmdi", ("OS Command Injection", "CWE-78")), ("command", ("OS Command Injection", "CWE-78")),
    ("xss", ("Reflected XSS", "CWE-79")),
    ("ssrf", ("SSRF", "CWE-918")),
    ("deserial", ("Insecure Deserialization", "CWE-502")), ("pickle", ("Insecure Deserialization", "CWE-502")),
    ("xxe", ("XXE", "CWE-611")), ("xml", ("XXE", "CWE-611")),
    ("path", ("Path Traversal", "CWE-22")), ("traversal", ("Path Traversal", "CWE-22")),
    ("redirect", ("Open Redirect", "CWE-601")),
    ("secret", ("Hardcoded Secret", "CWE-798")), ("hardcoded", ("Hardcoded Secret", "CWE-798")),
    ("idor", ("IDOR / Broken Authorization", "CWE-639")),
    ("broken_auth", ("Broken Authorization", "CWE-602")), ("auth", ("Broken Authorization", "CWE-285")),
    ("race", ("Race Condition (TOCTOU)", "CWE-367")), ("toctou", ("Race Condition (TOCTOU)", "CWE-367")),
    ("ssti", ("Server-Side Template Injection", "CWE-1336")), ("template", ("Server-Side Template Injection", "CWE-1336")),
    ("crlf", ("HTTP Response Splitting", "CWE-113")),
    ("cookie", ("Sensitive Cookie Without Flags", "CWE-614")),
    ("tls", ("Improper TLS Verification", "CWE-295")),
    ("ldap", ("LDAP Injection", "CWE-90")),
    ("xpath", ("XPath Injection", "CWE-643")),
    ("nosqli", ("NoSQL Injection", "CWE-943")), ("nosql", ("NoSQL Injection", "CWE-943")),
    ("random", ("Insecure Randomness", "CWE-330")),
    ("code_injection", ("Code Injection", "CWE-94")), ("eval", ("Code Injection", "CWE-94")),
    ("file_perms", ("Overly Permissive File Permissions", "CWE-732")), ("perms", ("Overly Permissive File Permissions", "CWE-732")),
    ("sensitive_info", ("Sensitive Information Exposure", "CWE-200")), ("info", ("Sensitive Information Exposure", "CWE-200")),
    ("csrf", ("CSRF", "CWE-352")),
    ("redirect", ("Open Redirect", "CWE-601")),
    ("ratelimit", ("Missing Rate Limiting", "CWE-307")), ("rate", ("Missing Rate Limiting", "CWE-307")),
    ("missing_auth", ("Missing Authentication", "CWE-306")),
    ("return_taint", ("Tainted Return Flow", "CWE-20")),
    ("mass_assign", ("Mass Assignment", "CWE-915")),
    ("weakcrypto", ("Weak / Broken Cryptography", "CWE-327")),
    ("md5", ("Weak / Broken Cryptography", "CWE-327")),
    ("jwt", ("JWT Verification Weakness", "CWE-347")),
    ("cors", ("Permissive CORS", "CWE-942")),
    ("debug", ("Debug Mode / Verbose Errors", "CWE-489")),
    ("static_cred", ("Static Credential", "CWE-798")),
    ("authz", ("Broken Authorization", "CWE-285")),
    ("membership", ("Broken Authorization", "CWE-285")),
    ("ssti", ("Server-Side Template Injection", "CWE-1336")),
    ("missing_cap", ("Missing Authentication", "CWE-306")),
    ("deluser", ("Missing Authentication", "CWE-306")),
]
SEV = {"CWE-89": "HIGH", "CWE-78": "CRITICAL", "CWE-79": "MEDIUM", "CWE-918": "HIGH",
       "CWE-502": "CRITICAL", "CWE-611": "HIGH", "CWE-22": "HIGH", "CWE-601": "MEDIUM",
       "CWE-798": "HIGH", "CWE-639": "HIGH", "CWE-602": "HIGH", "CWE-285": "HIGH",
       "CWE-367": "HIGH", "CWE-1336": "HIGH", "CWE-113": "MEDIUM", "CWE-614": "LOW",
       "CWE-295": "HIGH", "CWE-90": "HIGH", "CWE-643": "MEDIUM", "CWE-943": "HIGH",
       "CWE-330": "MEDIUM", "CWE-94": "CRITICAL", "CWE-732": "MEDIUM", "CWE-200": "MEDIUM",
       "CWE-352": "MEDIUM", "CWE-307": "MEDIUM", "CWE-306": "HIGH", "CWE-915": "HIGH", "CWE-327": "MEDIUM", "CWE-347": "HIGH", "CWE-942": "MEDIUM", "CWE-489": "MEDIUM", "CWE-306": "HIGH",
       "CWE-20": "MEDIUM"}


def classify(fname):
    low = fname.lower()
    for kw, (vc, cwe) in KW:
        if kw in low:
            return vc, cwe
    return "Other", "CWE-693"


def main():
    existing = {}
    if os.path.exists(OUT):
        for c in json.load(open(OUT, encoding="utf-8")):
            existing[c.get("file")] = c

    out = []
    idx = 0
    for kind, d in DIRS.items():
        for fname in sorted(os.listdir(d)):
            if fname.startswith("."):
                continue
            idx += 1
            if fname in existing and existing[fname].get("_precise"):
                out.append(existing[fname])
                continue
            ext = os.path.splitext(fname)[1]
            vc, cwe = classify(fname)
            low = fname.lower()
            if "interproc" in low or "return_taint" in low or "chain" in low:
                diff = "hidden"
            elif kind == "safe":
                diff = "adversarial"  # safe = a trap by construction
            else:
                diff = "obvious"
            out.append({
                "id": f"LB-{idx:03d}",
                "file": fname,
                "title": fname.replace("_", " ").rsplit(".", 1)[0].title(),
                "cwe": cwe if kind == "vulnerable" else "N/A (safe)",
                "severity": SEV.get(cwe, "MEDIUM") if kind == "vulnerable" else "SAFE",
                "language": EXT_LANG.get(ext, "?"),
                "context": "Web Framework / WordPress",
                "type": kind,
                "difficulty": diff,
            })
    json.dump(out, open(OUT, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print(f"wrote {len(out)} entries to cases.json")


if __name__ == "__main__":
    main()
