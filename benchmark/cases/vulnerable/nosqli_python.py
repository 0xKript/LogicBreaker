from flask import Flask, request, jsonify
from pymongo import MongoClient
app = Flask(__name__)
products = MongoClient().db.products

@app.route("/search")
def search():
    category = request.args.get("category")
    # VULN: NoSQL injection - client value used as a query object (allows $ne/$gt/$regex)
    results = products.find({"category": category, "active": True})
    return jsonify(list(results))
