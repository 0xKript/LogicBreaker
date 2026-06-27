# SAFE: redirects to a fixed internal path. Trap: it reads a "next" request value
# (open-redirect shape), but the redirect target is a hardcoded constant, so the
# client value can never control the destination.
from flask import Flask, request, redirect
app = Flask(__name__)
@app.route("/login", methods=["POST"])
def login():
    _ = request.args.get("next")   # logged, never used as a target
    return redirect("/dashboard")
