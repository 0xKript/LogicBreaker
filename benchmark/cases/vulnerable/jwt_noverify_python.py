# VULN: JWT decoded WITHOUT signature verification in a request handler
# (an attacker can forge any token and impersonate any user).
import jwt
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/me")
def me():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    data = jwt.decode(token, options={"verify_signature": False})
    return jsonify(user=data["user"])
