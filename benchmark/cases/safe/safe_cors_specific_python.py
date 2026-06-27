# SAFE: a single trusted origin is echoed, never "*". Trap: an
# Access-Control-Allow-Origin header is set (the misconfig shape), but it is a
# fixed allow-listed origin, not a wildcard, and credentials stay scoped.
from flask import Flask, Response
app = Flask(__name__)
TRUSTED = "https://app.example.com"
@app.route("/data")
def data():
    r = Response("{}")
    r.headers["Access-Control-Allow-Origin"] = TRUSTED
    return r
