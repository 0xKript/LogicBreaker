# SAFE: the login endpoint is rate limited. Trap: it is an authentication action
# (brute-force target), but the limiter caps attempts per IP.
from flask import Flask, request
from flask_limiter import Limiter
app = Flask(__name__)
limiter = Limiter(app, key_func=lambda: request.remote_addr)
@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    return authenticate(request.form["user"], request.form["pass"])
