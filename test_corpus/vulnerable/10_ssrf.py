"""Vuln 10: SSRF via requests.get."""
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    resp = requests.get(url)
    return resp.text
