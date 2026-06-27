# VULN: redirects to a fully user-controlled URL (open redirect / phishing).
from flask import Flask, request, redirect
app = Flask(__name__)
@app.route("/go")
def go():
    return redirect(request.args.get("url"))
