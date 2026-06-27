"""Adversarial safe: subprocess with shell=False + argv list (correct)."""
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route("/convert")
def convert():
    filename = request.args.get("file", "")
    # shell=False + argv list = NO shell -> no command injection
    result = subprocess.run(["convert", filename, "out.png"],
                            capture_output=True, timeout=10)
    return result.stdout.decode()
