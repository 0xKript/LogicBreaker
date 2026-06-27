# VULN: reflected XSS via %-formatting of a request-tainted variable (CWE-79).
from flask import Flask, request
app = Flask(__name__)
@app.route("/hi")
def hi():
    name = request.args.get("name")
    return "<h1>Hello %s</h1>" % name
