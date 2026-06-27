from flask import Flask, request
from werkzeug.utils import secure_filename
app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    # SAFE look-alike: same upload-save shape, but secure_filename() strips path
    # components from the attacker-controlled filename before it is used.
    f = request.files["file"]
    f.save("uploads/" + secure_filename(f.filename))
    return "ok"
