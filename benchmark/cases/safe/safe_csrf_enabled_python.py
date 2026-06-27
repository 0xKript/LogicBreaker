# SAFE: a sensitive mutation protected on every axis. Trap: changing an account
# email is exactly the kind of action flagged when unprotected, but here CSRF is
# enforced app-wide (no exemption) AND the route requires an authenticated user.
from flask import Flask, request
from flask_wtf.csrf import CSRFProtect
from flask_login import login_required, current_user
app = Flask(__name__)
csrf = CSRFProtect(app)

@app.route("/account/email", methods=["POST"])
@login_required
def change_email():
    set_email(current_user.id, request.form["email"])
    return "updated"
