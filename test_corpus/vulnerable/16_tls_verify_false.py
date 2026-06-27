"""Vuln 16: TLS verification disabled."""
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route("/proxy")
def proxy():
    url = request.args.get("url", "")
    resp = requests.get(url, verify=False)
    return resp.text
