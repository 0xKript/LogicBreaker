"""Safe 09: yaml.safe_load (correct)."""
from flask import Flask, request
import yaml

app = Flask(__name__)

@app.route("/config", methods=["POST"])
def load_config():
    data = request.data.decode("utf-8")
    cfg = yaml.safe_load(data)
    return str(cfg)
