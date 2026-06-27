# VULN: requests.request() with a user-controlled URL (SSRF). Same flaw as
# requests.get(), reached through the generic request() entrypoint.
import requests
from flask import Flask, request
app = Flask(__name__)

@app.route("/proxy")
def proxy():
    target = request.args.get("url")
    return requests.request("GET", target).text   # attacker controls destination
