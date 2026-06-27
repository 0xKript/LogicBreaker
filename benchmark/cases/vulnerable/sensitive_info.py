from flask import Flask, request
import os
app = Flask(__name__)

@app.route("/config")
def config():
    return os.environ.get("SECRET_KEY")
