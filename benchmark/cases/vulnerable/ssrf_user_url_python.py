# VULN: fetches a URL taken straight from the request (SSRF).
import requests
from flask import Flask, request
app = Flask(__name__)

@app.route("/fetch")
def fetch():
    target = request.args.get("url")
    r = requests.get(target)              # attacker controls the destination
    return r.text
