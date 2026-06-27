# VULN: a hardcoded admin password compared directly (backdoor credential).
from flask import Flask, request
app = Flask(__name__)
@app.route("/admin/login", methods=["POST"])
def admin_login():
    if request.form.get("password") == "S3cr3tAdminP@ss!":
        return "welcome admin"
    return "denied", 403
