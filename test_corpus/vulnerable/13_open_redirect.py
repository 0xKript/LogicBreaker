"""Vuln 13: Open Redirect."""
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route("/login")
def login():
    next_url = request.args.get("next", "/")
    return redirect(next_url)
