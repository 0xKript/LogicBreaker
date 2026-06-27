"""Hidden: SSRF via urllib instead of requests."""
from flask import Flask, request
import urllib.request

app = Flask(__name__)

@app.route("/proxy")
def proxy():
    url = request.args.get("url", "")
    with urllib.request.urlopen(url) as resp:
        return resp.read().decode()
