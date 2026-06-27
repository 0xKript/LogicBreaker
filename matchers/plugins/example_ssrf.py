"""Example plugin matcher: SSRF detector. Drop-in, no engine changes needed."""
from matchers.base import BaseMatcher
from matchers import signals as S


class SSRFMatcher(BaseMatcher):
    id = "ssrf"
    name = "Server-Side Request Forgery (SSRF)"
    cwe = "CWE-918"
    default_severity = "HIGH"

    def match(self, unit, context):
        from matchers.builtin import _is_request_handler, _unit_has_route
        from matchers import signals as S
        import re
        if not (_is_request_handler(unit) or _unit_has_route(unit, context)):
            return []
        src = S._strip_doc_and_comments(unit["source"], unit.get("language",""))
        url_params = [p for p in unit.get("params", []) if any(k in p.lower() for k in ("url", "uri", "endpoint", "callback", "webhook"))]
        # also detect a url-like variable read from client input
        client_url = re.findall(
            r"(\w*(?:url|uri|endpoint|callback|webhook|host|link)\w*)\s*=\s*[^=\n]*"
            r"(?:request|req\.|params|\$_get|\$_post|get_json|\.json|\.form|\.args|\.body)",
            src, re.IGNORECASE)
        url_params = url_params + [u for u in client_url if u not in url_params]
        if not url_params:
            return []
        fetchy = any(t in src for t in ("requests.get", "requests.post", "requests.put", "urlopen",
                                        "fetch(", "http.get", "HttpClient", "curl_exec", "axios",
                                        "httpx.", "urllib.request"))
        if not fetchy:
            return []
        if any(t in src.lower() for t in ("allowlist", "whitelist", "is_allowed", "validate_url",
                                          "urlparse", "netloc", "_up(", "blocked outbound")):
            return []
        return [self._finding(
            self, unit, severity="HIGH", confidence=0.5,
            explanation=f"`{unit['qualname']}` issues an outbound request to a client-controlled URL ({', '.join(url_params)}) without allowlisting, enabling SSRF.",
            exploit_scenario="Point the URL at internal services (e.g. cloud metadata at 169.254.169.254) to exfiltrate credentials.",
            remediation="Allowlist destination hosts/schemes; block link-local and private ranges; resolve and re-validate DNS.",
        )]


MATCHERS = [SSRFMatcher()]
