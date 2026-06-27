# VULN: a state-changing endpoint explicitly exempted from CSRF protection.
from flask import Flask, request
from flask_wtf.csrf import CSRFProtect
app = Flask(__name__)
csrf = CSRFProtect(app)
@app.route("/account/email", methods=["POST"])
@csrf.exempt
def change_email():
    set_email(request.form["email"])
    return "updated"
