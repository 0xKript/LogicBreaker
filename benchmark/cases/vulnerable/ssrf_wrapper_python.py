# VULN: SSRF hidden behind an internal helper that fetches a user URL.
import requests
from flask import Flask, request
app = Flask(__name__)

def _fetch(url):
    return requests.get(url, timeout=5).text   # no host allow-list

@app.route("/preview")
def preview():
    return _fetch(request.args.get("target"))
