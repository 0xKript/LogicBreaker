"""
Vulnerability Knowledge Base (VKB) -- the single source of truth
================================================================

Every vulnerability class the tool understands is described ONCE here, as a
declarative record. Detection, classification, severity scoring and (later) the
fixer registry all read from this table instead of hard-coding per-class facts
in scattered constants (the old ``CLASS_META`` lived inside the taint engine and
froze severity to a single value per type -- which is wrong, because the SAME
vulnerability class has different severity depending on context).

Each ``VulnClass`` carries:

  * the canonical name + its CWE id, the CWE's human name, and its MITRE PARENT
    CWE (so a finding can show its lineage, e.g. CWE-89 -> CWE-943 -> CWE-707),
  * which detection LAYER is responsible for it (taint / structural / llm),
  * a BASE CVSS 1 vector (the severity in the *typical* context),
  * a set of context MODIFIERS: named signals that, when present, override
    specific CVSS metrics (this is what turns one SSRF into Low and another into
    Critical -- same class, different reachable impact),
  * a one-line description of the root-cause FIX FAMILY.

Adding a new vulnerability class to the whole tool is therefore a single entry
here plus registering its detector -- no surgery in the engine core.

NOTE on regex vs AST: nothing in this file detects anything. It is pure
metadata. Detection stays AST/taint-based in the engine; this table only tells
the rest of the pipeline what a *already-detected* finding MEANS.
"""

from __future__ import annotations
from dataclasses import dataclass, field


# ----------------------------------------------------------------------------
# CVSS 1 vector -- only the eight Base metrics. Stored as the short codes used
# in the official vector string so we can render it verbatim for transparency.
#   AV: N(etwork) A(djacent) L(ocal) P(hysical)
#   AC: L(ow) H(igh)        PR: N(one) L(ow) H(igh)        UI: N(one) R(equired)
#   S : U(nchanged) C(hanged)        C/I/A: N(one) L(ow) H(igh)
# ----------------------------------------------------------------------------
@dataclass(frozen=True)
class CVSSVector:
    AV: str = "N"
    AC: str = "L"
    PR: str = "N"
    UI: str = "N"
    S: str = "U"
    C: str = "N"
    I: str = "N"
    A: str = "N"

    def with_overrides(self, overrides: dict) -> "CVSSVector":
        """Return a NEW vector with the given metric(s) replaced. Used to apply a
        context modifier without mutating the shared base vector."""
        data = {"AV": self.AV, "AC": self.AC, "PR": self.PR, "UI": self.UI,
                "S": self.S, "C": self.C, "I": self.I, "A": self.A}
        for k, v in overrides.items():
            if k in data:
                data[k] = v
        return CVSSVector(**data)

    def string(self) -> str:
        return (f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}/UI:{self.UI}"
                f"/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}")


@dataclass(frozen=True)
class Modifier:
    """A context signal -> CVSS metric override, with a human reason that is
    surfaced in the finding so the score is never a black box."""
    overrides: dict
    reason: str


@dataclass(frozen=True)
class VulnClass:
    name: str
    cwe: str
    cwe_name: str
    parent_cwe: str
    detection_layer: str            # "taint" | "structural" | "llm-verified"
    base_vector: CVSSVector
    fix_family: str
    # signal-name -> Modifier. Order matters: modifiers apply in insertion order.
    modifiers: dict = field(default_factory=dict)


# ----------------------------------------------------------------------------
# THE CATALOGUE. Keyed by CWE id (stable) -- name lookups fall back to this.
# Base vectors chosen to match real-world consensus scoring; modifiers encode
# the contextual swing the architecture doc demands ("same type, any severity").
# ----------------------------------------------------------------------------
_ENTRIES = {
    # --- Injection family (taint engine) ------------------------------------
    "CWE-78": VulnClass(
        name="OS Command Injection", cwe="CWE-78",
        cwe_name="Improper Neutralization of Special Elements used in an OS Command",
        parent_cwe="CWE-77", detection_layer="taint",
        # Shell RCE: full compromise of confidentiality, integrity, availability.
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
        fix_family="Pass an argv list and disable the shell (shell=False); never build a shell string.",
        modifiers={
            "auth_required": Modifier({"PR": "L"}, "Sink reachable only by an authenticated user."),
            "sandboxed_or_restricted": Modifier({"S": "U", "A": "L"}, "Execution appears constrained."),
        },
    ),
    "CWE-89": VulnClass(
        name="SQL Injection", cwe="CWE-89",
        cwe_name="Improper Neutralization of Special Elements used in an SQL Command",
        parent_cwe="CWE-943", detection_layer="taint",
        # Read-oriented by default: high confidentiality, low integrity impact.
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="L", A="N"),
        fix_family="Use parameterized / bound queries; keep data out of the SQL string.",
        modifiers={
            "write_operation": Modifier({"I": "H"}, "Statement modifies data (INSERT/UPDATE/DELETE/DDL)."),
            "auth_required": Modifier({"PR": "L"}, "Query reachable only by an authenticated user."),
            "stacked_or_admin": Modifier({"I": "H", "A": "H"}, "Stacked queries / DBA-level access possible."),
        },
    ),
    "CWE-22": VulnClass(
        name="Path Traversal", cwe="CWE-22",
        cwe_name="Improper Limitation of a Pathname to a Restricted Directory",
        parent_cwe="CWE-706", detection_layer="taint",
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
        fix_family="Resolve+confirm the path stays under an allowed root (realpath + startswith); basename user input.",
        modifiers={
            "write_operation": Modifier({"I": "H"}, "Path is opened for write/append -> arbitrary file write."),
            "auth_required": Modifier({"PR": "L"}, "File access reachable only by an authenticated user."),
        },
    ),
    "CWE-79": VulnClass(
        name="Reflected Cross-Site Scripting (XSS)", cwe="CWE-79",
        cwe_name="Improper Neutralization of Input During Web Page Generation",
        parent_cwe="CWE-74", detection_layer="structural",
        # Runs in the victim's browser (scope change); session/content theft.
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="L", I="L", A="N"),
        fix_family="HTML-escape user input before rendering, or return JSON; enable template auto-escaping.",
        modifiers={
            "auth_required": Modifier({"PR": "L"}, "Reflected sink reachable only by an authenticated user."),
        },
    ),
    "CWE-200": VulnClass(
        name="Sensitive Information Exposure", cwe="CWE-200",
        cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
        parent_cwe="CWE-668", detection_layer="structural",
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
        fix_family="Never return secrets/env to clients; expose only the specific non-sensitive fields needed.",
        modifiers={
            "stacked_or_admin": Modifier({"C": "H"}, "Exposes high-value secrets (keys/credentials)."),
        },
    ),
    "CWE-1336": VulnClass(
        name="Server-Side Template Injection", cwe="CWE-1336",
        cwe_name="Improper Neutralization of Special Elements Used in a Template Engine",
        parent_cwe="CWE-94", detection_layer="taint",
        # Jinja-style SSTI is typically RCE.
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
        fix_family="Render user data as a context value with autoescaping; never compile it as template source.",
        modifiers={
            "sandboxed_or_restricted": Modifier({"I": "L", "A": "N", "C": "H"}, "Template sandbox limits escape to RCE."),
            "auth_required": Modifier({"PR": "L"}, "Template reachable only by an authenticated user."),
        },
    ),
    "CWE-94": VulnClass(
        name="Code Injection", cwe="CWE-94",
        cwe_name="Improper Control of Generation of Code ('Code Injection')",
        parent_cwe="CWE-913", detection_layer="taint",
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
        fix_family="Remove eval/exec on untrusted data; use a safe parser or explicit dispatch table.",
        modifiers={"auth_required": Modifier({"PR": "L"}, "Reachable only by an authenticated user.")},
    ),
    "CWE-502": VulnClass(
        name="Insecure Deserialization", cwe="CWE-502",
        cwe_name="Deserialization of Untrusted Data",
        parent_cwe="CWE-913", detection_layer="taint",
        # pickle.loads on attacker data == trivial RCE.
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
        fix_family="Deserialize only trusted data; use a safe format (json / yaml.safe_load); no safe fix for pickle on user data.",
        modifiers={
            "needs_gadget": Modifier({"AC": "H"}, "Exploit depends on an available gadget chain."),
            "auth_required": Modifier({"PR": "L"}, "Reachable only by an authenticated user."),
        },
    ),
    # --- Request-forgery / redirect (taint, GUARD-aware) --------------------
    "CWE-918": VulnClass(
        name="Server-Side Request Forgery (SSRF)", cwe="CWE-918",
        cwe_name="Server-Side Request Forgery (SSRF)",
        parent_cwe="CWE-441", detection_layer="taint",
        # BASE: a plain outbound fetch of an attacker-influenced URL. Medium.
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
        fix_family="Validate the target host against an allowlist; block internal/link-local ranges before fetching.",
        modifiers={
            # the swing the user asked about: reaching internal services / cloud
            # metadata crosses a trust boundary (S:C) and exposes credentials (C:H).
            "sensitive_target": Modifier({"S": "C", "C": "H", "I": "L"},
                                         "Can reach internal services / cloud metadata (e.g. 169.254.169.254) -> credential theft."),
            "internal_reachable": Modifier({"S": "C", "C": "H"},
                                           "Can reach the internal network (read-only)."),
            # blind / out-of-band only, no response read back -> much lower.
            "blind": Modifier({"AC": "H", "C": "L", "I": "N"},
                              "Blind/out-of-band only; no response returned to the attacker."),
            "auth_required": Modifier({"PR": "L"}, "Reachable only by an authenticated user."),
        },
    ),
    "CWE-601": VulnClass(
        name="Open Redirect", cwe="CWE-601",
        cwe_name="URL Redirection to Untrusted Site ('Open Redirect')",
        parent_cwe="CWE-610", detection_layer="taint",
        # victim must click (UI:R), redirect leaves the app's origin (S:C).
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="N", A="N"),
        fix_family="Allowlist redirect targets; only permit same-origin or known hosts.",
        modifiers={
            "auth_context": Modifier({"C": "H"}, "Redirect occurs in an auth/OAuth flow -> token/credential theft."),
        },
    ),
    "CWE-611": VulnClass(
        name="XML External Entity (XXE)", cwe="CWE-611",
        cwe_name="Improper Restriction of XML External Entity Reference",
        parent_cwe="CWE-610", detection_layer="taint",
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="N", A="L"),
        fix_family="Disable external entity and DTD processing in the XML parser.",
        modifiers={"auth_required": Modifier({"PR": "L"}, "Reachable only by an authenticated user.")},
    ),
    # --- NEW injection families (taint) -------------------------------------
    "CWE-943": VulnClass(
        name="NoSQL Injection", cwe="CWE-943",
        cwe_name="Improper Neutralization of Special Elements in a Data Query Logic",
        parent_cwe="CWE-74", detection_layer="taint",
        # Operator injection ($ne/$gt/$where) -> auth bypass / data read.
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="L", A="N"),
        fix_family="Pass user input as a typed scalar (cast), never as a query object; reject $-operators.",
        modifiers={
            "where_js_eval": Modifier({"C": "H", "I": "H", "A": "H"}, "$where runs server-side JS -> code execution."),
            "auth_bypass": Modifier({"I": "H"}, "Injected operator bypasses an auth/login check."),
            "auth_required": Modifier({"PR": "L"}, "Query reachable only by an authenticated user."),
        },
    ),
    "CWE-90": VulnClass(
        name="LDAP Injection", cwe="CWE-90",
        cwe_name="Improper Neutralization of Special Elements used in an LDAP Query",
        parent_cwe="CWE-74", detection_layer="taint",
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="L", A="N"),
        fix_family="Escape filter/DN metacharacters (escape_filter_chars / escape_dn_chars).",
        modifiers={
            "auth_bypass": Modifier({"I": "H"}, "Filter injection bypasses an LDAP-bind auth check."),
            "auth_required": Modifier({"PR": "L"}, "Query reachable only by an authenticated user."),
        },
    ),
    "CWE-643": VulnClass(
        name="XPath Injection", cwe="CWE-643",
        cwe_name="Improper Neutralization of Data within XPath Expressions",
        parent_cwe="CWE-74", detection_layer="taint",
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
        fix_family="Use parameterized XPath (variables) or escape; never concatenate input into the expression.",
        modifiers={
            "auth_bypass": Modifier({"I": "H"}, "Expression injection bypasses an XML-backed auth check."),
            "auth_required": Modifier({"PR": "L"}, "Query reachable only by an authenticated user."),
        },
    ),
    "CWE-113": VulnClass(
        name="HTTP Response Splitting / CRLF Injection", cwe="CWE-113",
        cwe_name="Improper Neutralization of CRLF Sequences in HTTP Headers",
        parent_cwe="CWE-93", detection_layer="taint",
        # CRLF in a header -> response splitting, header/cookie injection.
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N"),
        fix_family="Strip CR/LF from header values (or reject them); never put raw input in a header.",
        modifiers={
            "sets_cookie_or_auth_header": Modifier({"I": "H"}, "Injected into a Set-Cookie / auth header -> session fixation."),
            "auth_required": Modifier({"PR": "L"}, "Header set only on an authenticated path."),
        },
    ),
    # --- Access control / auth (structural) ---------------------------------
    "CWE-639": VulnClass(
        name="Insecure Direct Object Reference", cwe="CWE-639",
        cwe_name="Authorization Bypass Through User-Controlled Key",
        parent_cwe="CWE-863", detection_layer="structural",
        # needs a session (PR:L); reads another user's object (C:H).
        base_vector=CVSSVector(AV="N", AC="L", PR="L", UI="N", S="U", C="H", I="N", A="N"),
        fix_family="Enforce an ownership/authorization check tying the object to the current principal.",
        modifiers={
            "write_operation": Modifier({"I": "H"}, "The reference allows modifying another user's object."),
            "no_auth": Modifier({"PR": "N"}, "No authentication required to reach it."),
        },
    ),
    "CWE-602": VulnClass(
        name="Broken Authorization (client-controlled role)", cwe="CWE-602",
        cwe_name="Client-Side Enforcement of Server-Side Security",
        parent_cwe="CWE-863", detection_layer="structural",
        base_vector=CVSSVector(AV="N", AC="L", PR="L", UI="N", S="U", C="H", I="H", A="N"),
        fix_family="Enforce the privilege/role decision on the server from a trusted session, not from client input.",
        modifiers={"no_auth": Modifier({"PR": "N"}, "No authentication required to reach it.")},
    ),
    "CWE-306": VulnClass(
        name="Missing Authentication", cwe="CWE-306",
        cwe_name="Missing Authentication for Critical Function",
        parent_cwe="CWE-862", detection_layer="structural",
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
        fix_family="Require authentication on the sensitive endpoint before performing the action.",
        modifiers={},
    ),
    "CWE-287": VulnClass(
        name="Broken Authentication (static credential)", cwe="CWE-287",
        cwe_name="Improper Authentication",
        parent_cwe="CWE-1211", detection_layer="structural",
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
        fix_family="Compare secrets in constant time (hmac.compare_digest) and load them from config, not source.",
        modifiers={},
    ),
    "CWE-347": VulnClass(
        name="JWT Verification Weakness", cwe="CWE-347",
        cwe_name="Improper Verification of Cryptographic Signature",
        parent_cwe="CWE-345", detection_layer="structural",
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
        fix_family="Verify the signature with a fixed algorithm allowlist; reject 'none' and unverified tokens.",
        modifiers={},
    ),
    # --- Secrets / crypto / config (structural) -----------------------------
    "CWE-798": VulnClass(
        name="Hardcoded Secret / Credential", cwe="CWE-798",
        cwe_name="Use of Hard-coded Credentials",
        parent_cwe="CWE-344", detection_layer="structural",
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="L", A="N"),
        fix_family="Load secrets from environment/secret manager; rotate the exposed value.",
        modifiers={
            "local_only": Modifier({"AV": "L", "C": "L"}, "Secret only usable from local context."),
        },
    ),
    "CWE-327": VulnClass(
        name="Weak / Broken Cryptography", cwe="CWE-327",
        cwe_name="Use of a Broken or Risky Cryptographic Algorithm",
        parent_cwe="CWE-693", detection_layer="structural",
        base_vector=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="L", A="N"),
        fix_family="Replace MD5/SHA1/DES/ECB with a modern primitive (SHA-256+, AES-GCM, bcrypt/argon2).",
        modifiers={
            "password_storage": Modifier({"C": "H"}, "Used to protect passwords -> mass credential exposure."),
        },
    ),
    "CWE-942": VulnClass(
        name="Permissive CORS Configuration", cwe="CWE-942",
        cwe_name="Permissive Cross-domain Policy with Untrusted Domains",
        parent_cwe="CWE-668", detection_layer="structural",
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="N", A="N"),
        fix_family="Reflect only allowlisted origins; never combine wildcard origin with credentials.",
        modifiers={
            "with_credentials": Modifier({"C": "H"}, "Wildcard origin combined with credentials -> session data theft."),
        },
    ),
    "CWE-489": VulnClass(
        name="Debug Mode / Verbose Errors", cwe="CWE-489",
        cwe_name="Active Debug Code",
        parent_cwe="CWE-710", detection_layer="structural",
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
        fix_family="Disable debug mode and verbose error pages in production.",
        modifiers={
            "console_enabled": Modifier({"C": "H", "I": "H"}, "Interactive debugger/console exposed -> RCE."),
        },
    ),
    "CWE-915": VulnClass(
        name="Mass Assignment / Over-posting", cwe="CWE-915",
        cwe_name="Improperly Controlled Modification of Dynamically-Determined Object Attributes",
        parent_cwe="CWE-913", detection_layer="structural",
        base_vector=CVSSVector(AV="N", AC="L", PR="L", UI="N", S="U", C="L", I="H", A="N"),
        fix_family="Bind only an explicit allowlist of fields; never spread request data into a model.",
        modifiers={"privilege_field": Modifier({"C": "H"}, "Allows setting a privilege/role field -> escalation.")},
    ),
    # --- Concurrency / business logic ---------------------------------------
    "CWE-367": VulnClass(
        name="Race Condition (TOCTOU)", cwe="CWE-367",
        cwe_name="Time-of-check Time-of-use (TOCTOU) Race Condition",
        parent_cwe="CWE-362", detection_layer="structural",
        base_vector=CVSSVector(AV="N", AC="H", PR="L", UI="N", S="U", C="L", I="H", A="L"),
        fix_family="Make the check-and-act atomic (lock / SELECT ... FOR UPDATE / compare-and-swap).",
        modifiers={"financial": Modifier({"I": "H", "A": "N", "C": "L"}, "Affects balance/inventory -> monetary impact.")},
    ),
    "CWE-307": VulnClass(
        name="Missing Rate Limiting", cwe="CWE-307",
        cwe_name="Improper Restriction of Excessive Authentication Attempts",
        parent_cwe="CWE-799", detection_layer="structural",
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="L"),
        fix_family="Add per-identity rate limiting / lockout on the sensitive endpoint.",
        modifiers={},
    ),
    "CWE-840": VulnClass(
        name="Business Logic (Price/Quantity Manipulation)", cwe="CWE-840",
        cwe_name="Business Logic Errors",
        parent_cwe="CWE-840", detection_layer="structural",
        base_vector=CVSSVector(AV="N", AC="L", PR="L", UI="N", S="U", C="N", I="H", A="N"),
        fix_family="Validate quantities/prices server-side against trusted bounds before use.",
        modifiers={},
    ),
    # --- configuration / hardening family ----------------------------------
    "CWE-295": VulnClass(
        name="Disabled TLS Certificate Verification", cwe="CWE-295",
        cwe_name="Improper Certificate Validation",
        parent_cwe="CWE-287", detection_layer="structural",
        base_vector=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="H", A="N"),
        fix_family="Keep TLS verification on (verify=True); trust the system CA store or pin a known CA.",
        modifiers={"sends_credentials": Modifier({"AC": "L", "C": "H", "I": "H"},
                                                 "Credentials/secrets sent over the unverified channel.")},
    ),
    "CWE-1004": VulnClass(
        name="Insecure Cookie Flags (session/auth)", cwe="CWE-1004",
        cwe_name="Sensitive Cookie Without 'HttpOnly' Flag",
        parent_cwe="CWE-732", detection_layer="structural",
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="H", I="L", A="N"),
        fix_family="Set HttpOnly + Secure + SameSite on every session/auth cookie.",
        modifiers={"no_secure_flag": Modifier({"AC": "L"}, "No Secure flag -> cookie also sniffable over HTTP.")},
    ),
    "CWE-352": VulnClass(
        name="CSRF Protection Disabled", cwe="CWE-352",
        cwe_name="Cross-Site Request Forgery (CSRF)",
        parent_cwe="CWE-345", detection_layer="structural",
        base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="H", A="L"),
        fix_family="Keep CSRF protection on; use per-request tokens or SameSite cookies + origin checks.",
        modifiers={},
    ),
    "CWE-330": VulnClass(
        name="Insecure Randomness for Security Value", cwe="CWE-330",
        cwe_name="Use of Insufficiently Random Values",
        parent_cwe="CWE-693", detection_layer="structural",
        base_vector=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="H", A="N"),
        fix_family="Use the `secrets` module (token_urlsafe / randbelow) for all security values.",
        modifiers={"password_reset": Modifier({"AC": "L", "I": "H"},
                                              "Predictable value gates a password reset / account takeover.")},
    ),
    "CWE-732": VulnClass(
        name="Overly Permissive File Permissions", cwe="CWE-732",
        cwe_name="Incorrect Permission Assignment for Critical Resource",
        parent_cwe="CWE-732", detection_layer="structural",
        base_vector=CVSSVector(AV="L", AC="L", PR="L", UI="N", S="U", C="L", I="H", A="L"),
        fix_family="Grant least privilege (0o600 for secrets, 0o644 for read-only data); never world-writable.",
        modifiers={},
    ),
    "CWE-377": VulnClass(
        name="Insecure Temporary File", cwe="CWE-377",
        cwe_name="Insecure Temporary File",
        parent_cwe="CWE-668", detection_layer="structural",
        # Local TOCTOU: predictable temp name lets a local attacker pre-create or
        # symlink the path before it is opened.
        base_vector=CVSSVector(AV="L", AC="H", PR="L", UI="N", S="U", C="L", I="H", A="L"),
        fix_family="Use tempfile.mkstemp()/NamedTemporaryFile() which atomically create a uniquely-named file.",
        modifiers={},
    ),
}

# Name -> CWE alias map so we can resolve findings that only carry a type string.
# Keys are normalized (lowercase, trimmed) and matched on a prefix basis too.
_NAME_TO_CWE = {vc.name.lower(): cwe for cwe, vc in _ENTRIES.items()}
_NAME_TO_CWE.update({
    "os command injection": "CWE-78",
    "command injection": "CWE-78",
    "sql injection": "CWE-89",
    "reflected cross-site scripting (xss)": "CWE-79",
    "cross-site scripting (xss)": "CWE-79",
    "cross-site scripting": "CWE-79",
    "reflected xss": "CWE-79",
    "xss": "CWE-79",
    "sensitive information exposure": "CWE-200",
    "information disclosure": "CWE-200",
    "sensitive data exposure": "CWE-200",
    "path traversal": "CWE-22",
    "server-side template injection": "CWE-1336",
    "code injection": "CWE-94",
    "insecure deserialization": "CWE-502",
    "server-side request forgery (ssrf)": "CWE-918",
    "server-side request forgery": "CWE-918",
    "ssrf": "CWE-918",
    "open redirect": "CWE-601",
    "xml external entity (xxe)": "CWE-611",
    "xxe": "CWE-611",
    "insecure direct object reference": "CWE-639",
    "idor": "CWE-639",
    "broken authorization (client-controlled role)": "CWE-602",
    "broken authorization": "CWE-602",
    "missing authentication": "CWE-306",
    "broken authentication (static credential)": "CWE-287",
    "broken authentication": "CWE-287",
    "jwt verification weakness": "CWE-347",
    "hardcoded secret / credential": "CWE-798",
    "hardcoded secret": "CWE-798",
    "weak / broken cryptography": "CWE-327",
    "weak cryptography": "CWE-327",
    "permissive cors configuration": "CWE-942",
    "debug mode / verbose errors": "CWE-489",
    "mass assignment / over-posting": "CWE-915",
    "race condition (toctou)": "CWE-367",
    "missing rate limiting": "CWE-307",
    "nosql injection": "CWE-943",
    "ldap injection": "CWE-90",
    "xpath injection": "CWE-643",
    "http response splitting / crlf injection": "CWE-113",
    "crlf injection": "CWE-113",
    "insecure temporary file": "CWE-377",
    "insecure temp file": "CWE-377",
})

# Generic fallback for a finding whose class we don't model yet: conservative
# Medium, so the severity engine never crashes and never over-claims.
_FALLBACK = VulnClass(
    name="Unclassified Finding", cwe="CWE-20",
    cwe_name="Improper Input Validation", parent_cwe="CWE-707",
    detection_layer="structural",
    base_vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="L", A="N"),
    fix_family="Validate and constrain the input at the trust boundary.",
    modifiers={},
)


def resolve(cwe: str = "", type_name: str = "") -> VulnClass:
    """Look up a VulnClass by CWE id first (most stable), then by type name.
    Falls back to a conservative Medium record so callers never get None."""
    if cwe:
        key = cwe.strip().upper()
        if not key.startswith("CWE-"):
            key = "CWE-" + key.lstrip("CWE").lstrip("-")
        if key in _ENTRIES:
            return _ENTRIES[key]
    if type_name:
        n = type_name.strip().lower()
        if n in _NAME_TO_CWE:
            return _ENTRIES[_NAME_TO_CWE[n]]
        # prefix match for truncated/variant names ("Broken Authorization (clien...")
        for name, cwe_id in _NAME_TO_CWE.items():
            if n.startswith(name[:18]) or name.startswith(n[:18]):
                return _ENTRIES[cwe_id]
    return _FALLBACK


def all_classes():
    """Iterate every modelled class (for reporting / coverage listing)."""
    return list(_ENTRIES.values())
