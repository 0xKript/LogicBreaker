# VULN: all request fields are written onto the user object (privilege fields
# like is_admin can be over-posted).
from flask import Flask, request
app = Flask(__name__)
@app.route("/profile", methods=["POST"])
def profile():
    user = get_current_user()
    for key, value in request.json.items():
        setattr(user, key, value)
    user.save()
    return "ok"
