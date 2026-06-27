"""Safe 05: Path traversal prevented via secure_filename + containment check."""
from flask import Flask, request, send_file
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
UPLOAD_DIR = "/var/www/uploads"

@app.route("/file")
def get_file():
    name = request.args.get("name", "")
    safe_name = secure_filename(name)
    path = os.path.join(UPLOAD_DIR, safe_name)
    # defence in depth: verify the resolved path stays under UPLOAD_DIR
    if not os.path.realpath(path).startswith(UPLOAD_DIR):
        return "forbidden", 403
    return send_file(path)
