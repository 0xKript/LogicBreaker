"""Hidden: command injection via subprocess shell=True with concat."""
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route("/convert")
def convert():
    filename = request.args.get("file", "")
    # subtle: shell=True + string concat -> RCE even though subprocess is used
    result = subprocess.run("convert " + filename + " out.png",
                            shell=True, capture_output=True)
    return result.stdout.decode()
