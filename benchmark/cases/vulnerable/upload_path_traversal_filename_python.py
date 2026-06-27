from flask import Flask, request
app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    # VULN: the attacker-controlled upload .filename is concatenated into the
    # save path with no sanitisation -> path traversal (e.g. "../../etc/x").
    f = request.files["file"]
    f.save("uploads/" + f.filename)
    return "ok"
