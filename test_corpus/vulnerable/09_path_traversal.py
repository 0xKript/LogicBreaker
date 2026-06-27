"""Vuln 09: Path Traversal via open()."""
from flask import Flask, request, send_file

app = Flask(__name__)

@app.route("/file")
def get_file():
    name = request.args.get("name", "")
    path = "/var/www/uploads/" + name
    return send_file(path)
