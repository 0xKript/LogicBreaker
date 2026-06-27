from flask import Flask, request
app = Flask(__name__)

@app.route("/file")
def read_file():
    fname = request.args.get("file")
    # VULN: path traversal
    with open("/data/" + fname) as f:
        return f.read()
