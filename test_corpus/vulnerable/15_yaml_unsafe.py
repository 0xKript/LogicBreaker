"""Vuln 15: Insecure Deserialization via yaml.load (no SafeLoader)."""
from flask import Flask, request
import yaml

app = Flask(__name__)

@app.route("/config", methods=["POST"])
def load_config():
    data = request.data.decode("utf-8")
    cfg = yaml.load(data)
    return str(cfg)
