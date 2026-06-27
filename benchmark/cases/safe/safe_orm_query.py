from flask import Flask, request
app = Flask(__name__)
@app.route("/user")
def get_user():
    uid = request.args.get("id")
    # SAFE: ORM with parameter binding, no raw SQL
    return User.query.filter_by(id=uid).first()
