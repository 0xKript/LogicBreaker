# VULN: subprocess with shell=True and request data.
import subprocess
from flask import Flask, request
app = Flask(__name__)

@app.route("/dns")
def dns():
    host = request.args.get("host")
    return subprocess.check_output("nslookup " + host, shell=True)
