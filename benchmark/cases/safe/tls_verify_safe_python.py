import requests
from flask import Flask, request
app = Flask(__name__)

@app.route("/fetch")
def fetch():
    # SAFE: certificate verification left on
    return requests.get("https://api.internal/data", verify=True).text
