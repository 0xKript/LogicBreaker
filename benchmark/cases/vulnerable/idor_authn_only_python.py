from flask import Flask, jsonify
from flask_login import login_required
app = Flask(__name__)

@app.route("/order/<order_id>")
@login_required
def get_order(order_id):
    # VULN: @login_required proves the user is LOGGED IN, not that they OWN this
    # order. Any authenticated user can read any order_id -> IDOR.
    order = Order.query.get(order_id)
    return jsonify(order.to_dict())
