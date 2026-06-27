# VULN: server environment/config returned straight to the client (info leak of
# secrets such as DB credentials and API keys held in env vars).
import os
from flask import Flask, jsonify
app = Flask(__name__)
@app.route("/debug/config")
def debug_config():
    return jsonify(environment=dict(os.environ), settings=str(app.config))
