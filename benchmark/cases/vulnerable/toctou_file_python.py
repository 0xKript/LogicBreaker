# VULN: time-of-check/time-of-use race -- the path is checked then written in two
# steps; an attacker can swap it (symlink) in the window between check and use.
import os
from flask import Flask, request
app = Flask(__name__)
@app.route("/save", methods=["POST"])
def save_upload():
    path = "/var/spool/" + request.form["name"]
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(request.form["data"])
    return "ok"
