"""Vuln 17: CORS wildcard with credentials."""
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins="*", supports_credentials=True)

@app.route("/")
def home():
    return "ok"
