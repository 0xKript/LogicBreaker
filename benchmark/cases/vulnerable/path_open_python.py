# VULN: user-controlled filename joined onto a base and opened (path traversal).
import os
from flask import Flask, request
app = Flask(__name__)
@app.route("/read")
def read():
    fn = request.args.get("file")
    return open(os.path.join("/var/data", fn)).read()
