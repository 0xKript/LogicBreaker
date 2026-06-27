"""Hidden: XSS via string format (not concatenation)."""
from flask import Flask, request

app = Flask(__name__)

@app.route("/welcome")
def welcome():
    user = request.args.get("user", "")
    # f-string into HTML without escaping -> XSS
    return f"<h1>Welcome {user}</h1><p>Your session: {user}</p>"
