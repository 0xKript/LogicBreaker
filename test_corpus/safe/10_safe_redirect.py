"""Safe 10: Open redirect prevented via allowlist."""
from flask import Flask, request, redirect

app = Flask(__name__)
ALLOWED_REDIRECTS = {"/dashboard", "/profile", "/home"}

@app.route("/login")
def login():
    next_url = request.args.get("next", "/")
    if next_url not in ALLOWED_REDIRECTS:
        return redirect("/")
    return redirect(next_url)
