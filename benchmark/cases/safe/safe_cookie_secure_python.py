# SAFE: the session cookie sets Secure + HttpOnly + SameSite. Trap: it is a
# set_cookie call (the spot where missing flags are a vuln), but all protective
# flags are present.
from flask import Flask, make_response
app = Flask(__name__)
@app.route("/login")
def login():
    resp = make_response("ok")
    resp.set_cookie("session", "abc123", secure=True, httponly=True, samesite="Strict")
    return resp
