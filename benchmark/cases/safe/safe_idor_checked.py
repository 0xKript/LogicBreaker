from flask import Flask, request, jsonify, session
app = Flask(__name__)
DB = {1: {"owner": "a"}, 2: {"owner": "b"}}

@app.route("/doc/<doc_id>")
def get_doc(doc_id):
    doc = DB.get(int(doc_id))
    # SAFE: ownership check present
    if doc and doc["owner"] == session.get("user"):
        return jsonify(doc)
    return "forbidden", 403
