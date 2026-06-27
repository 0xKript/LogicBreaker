# VULN: the privilege level is taken from the client request and trusted.
from flask import Flask, request
app = Flask(__name__)
@app.route("/admin/action", methods=["POST"])
def admin_action():
    role = request.form.get("role")
    if role == "admin":
        return delete_all_records()
    return "denied", 403
