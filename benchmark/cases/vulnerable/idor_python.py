from flask import Flask, request, jsonify
app = Flask(__name__)
DB = {1: {"owner": "a"}, 2: {"owner": "b"}}

@app.route("/doc/<doc_id>")
def get_doc(doc_id):
    # VULN: IDOR - no ownership check
    return jsonify(DB.get(int(doc_id)))
