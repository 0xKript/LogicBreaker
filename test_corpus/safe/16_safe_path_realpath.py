"""Adversarial safe: path traversal prevented via realpath + startswith."""
from flask import Flask, request, send_file
import os

app = Flask(__name__)
BASE = "/var/www/uploads"

@app.route("/read")
def read_file():
    name = request.args.get("name", "")
    path = os.path.join(BASE, name)
    real = os.path.realpath(path)
    # containment check: resolved path must stay under BASE
    if not real.startswith(BASE + "/"):
        return "forbidden", 403
    return send_file(real)
