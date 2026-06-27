from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/product")
def product():
    pid = request.args.get("id")
    return jsonify({"product_id": pid, "in_stock": True})
