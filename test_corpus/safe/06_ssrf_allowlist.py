"""Safe 06: SSRF prevented via allowlist."""
from flask import Flask, request
import requests
from urllib.parse import urlparse

app = Flask(__name__)
ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}

@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        return "blocked", 403
    resp = requests.get(url)
    return resp.text
