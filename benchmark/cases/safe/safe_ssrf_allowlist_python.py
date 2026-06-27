# SAFE: the destination host must be on a fixed allow-list before any request is
# made. Trap: it fetches a user-provided URL (classic SSRF), but the host check
# blocks internal/metadata targets.
import requests
from urllib.parse import urlparse
from flask import request, abort
ALLOWED = {"api.example.com", "cdn.example.com"}
def fetch():
    url = request.args.get("url", "")
    if urlparse(url).hostname not in ALLOWED:
        abort(400)
    return requests.get(url, timeout=5).text
