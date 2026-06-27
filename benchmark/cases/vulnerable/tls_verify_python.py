import requests
from flask import Flask, request
app = Flask(__name__)

@app.route("/fetch")
def fetch():
    # VULN: TLS verification disabled - accepts any certificate (MITM)
    return requests.get("https://api.internal/data", verify=False).text
