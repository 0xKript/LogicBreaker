"""Vuln 20: JWT decode without signature verification."""
import jwt
from flask import Flask, request

app = Flask(__name__)

@app.route("/decode")
def decode_token():
    token = request.args.get("token", "")
    payload = jwt.decode(token, options={"verify_signature": False})
    return str(payload)
