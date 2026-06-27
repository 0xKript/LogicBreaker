from flask import Flask, request
from extensions import limiter
app = Flask(__name__)

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    # SAFE: rate limiting applied as a decorator
    pw = request.form.get("password")
    user = db.fetchone("SELECT * FROM users WHERE name = ?", (request.form.get("u"),))
    if user and check_password(user, pw):
        return "ok"
    return "no", 401
