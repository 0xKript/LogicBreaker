# VULN: a hardcoded master API key compared in plaintext to guard a privileged
# action (anyone reading the source obtains the key; it can never be rotated).
from flask import Flask, request
app = Flask(__name__)
MASTER_KEY = "static-master-key-7f3a9b2c1d"

@app.route("/api/admin/wipe", methods=["POST"])
def admin_wipe():
    api_key = request.headers.get("X-Api-Key", "")
    if api_key == MASTER_KEY:
        return wipe_all_logs()
    return "denied", 403
