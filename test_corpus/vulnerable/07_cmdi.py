"""Vuln 07: OS Command Injection."""
from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    result = os.system("ping -c 1 " + host)
    return f"result: {result}"
