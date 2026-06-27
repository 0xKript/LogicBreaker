from flask import Flask, request
import os
app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host")
    # VULN: OS command injection
    os.system("ping -c 1 " + host)
    return "done"
