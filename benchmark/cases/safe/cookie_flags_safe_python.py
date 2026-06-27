from flask import Flask, make_response
app = Flask(__name__)

@app.route("/signin")
def signin():
    resp = make_response("ok")
    # SAFE: HttpOnly + Secure + SameSite set
    resp.set_cookie("session_token", "abc123", httponly=True, secure=True, samesite="Lax")
    return resp
