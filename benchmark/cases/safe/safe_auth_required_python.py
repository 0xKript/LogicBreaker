# SAFE: the destructive endpoint is gated by an auth decorator. Trap: it deletes a
# user (sensitive-action shape), but @login_required + an admin check enforce
# authentication and authorization before the delete runs.
from flask import Flask, abort
from flask_login import login_required, current_user
from models import User
app = Flask(__name__)
@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
@login_required
def delete_user(uid):
    if not current_user.is_admin:
        abort(403)
    User.query.filter_by(id=uid).delete()
    return "ok"
