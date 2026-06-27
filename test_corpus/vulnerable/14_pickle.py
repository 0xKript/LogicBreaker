"""Vuln 14: Insecure Deserialization via pickle."""
from flask import Flask, request
import pickle

app = Flask(__name__)

@app.route("/load", methods=["POST"])
def load_data():
    data = request.data
    obj = pickle.loads(data)
    return str(obj)
