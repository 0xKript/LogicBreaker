"""Safe 04: Subprocess with shell=False and argv list (correct)."""
from flask import Flask, request
import subprocess
import shlex

app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # safe: shell=False + argv list -- no shell metacharacters
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, timeout=10)
    return result.stdout.decode()
