# VULN: reflects any origin with credentials allowed (CORS misconfig).
from flask import Flask, Response
app = Flask(__name__)
@app.route("/api")
def api():
    r = Response("{}")
    r.headers["Access-Control-Allow-Origin"] = "*"
    r.headers["Access-Control-Allow-Credentials"] = "true"
    return r
