# SAFE: requests.request() to a host that must be on a fixed allow-list. Trap:
# fetches a user-provided URL via the generic request() entrypoint (SSRF shape),
# but the host check blocks internal/metadata targets before any request is made.
import requests
from urllib.parse import urlparse
from flask import request, abort
ALLOWED = {"api.example.com", "cdn.example.com"}
def fetch():
    url = request.args.get("url", "")
    if urlparse(url).hostname not in ALLOWED:
        abort(400)
    return requests.request("GET", url, timeout=5).text
