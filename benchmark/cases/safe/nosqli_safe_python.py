from flask import Flask, request, jsonify
from pymongo import MongoClient
app = Flask(__name__)
products = MongoClient().db.products

@app.route("/search")
def search():
    category = request.args.get("category")
    # SAFE: input forced to a scalar -> operators cannot be injected
    results = products.find({"category": str(category), "active": True})
    return jsonify(list(results))
