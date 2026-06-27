"""Hidden: path traversal via os.path.join (does NOT prevent traversal)."""
from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/read")
def read_file():
    name = request.args.get("name", "")
    # os.path.join does NOT prevent traversal: join("/uploads", "../../etc/passwd")
    path = os.path.join("/var/www/uploads", name)
    with open(path) as f:
        return f.read()
