from flask import Flask, request
import os
app = Flask(__name__)
@app.route("/file")
def read_file():
    fname = request.args.get("file")
    # SAFE: validated with basename
    safe = os.path.basename(fname)
    with open("/data/" + safe) as f:
        return f.read()
