"""Vuln 04: Debug mode enabled in production."""
from flask import Flask
app = Flask(__name__)
app.debug = True

@app.route("/")
def home():
    return "hello"
