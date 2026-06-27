from flask import Flask, request
import pickle
app = Flask(__name__)

@app.route("/load", methods=["POST"])
def load():
    data = request.get_data()
    # VULN: insecure deserialization
    return str(pickle.loads(data))
