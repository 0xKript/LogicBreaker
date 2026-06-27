# VULN: deletes a directory tree at a user-controlled path (path traversal ->
# arbitrary deletion). No basename()/containment check, so `../` escapes the root.
import shutil
from flask import Flask, request
app = Flask(__name__)

@app.route("/cache/clear", methods=["POST"])
def clear_cache():
    name = request.args.get("dir")
    shutil.rmtree("/var/cache/app/" + name)   # ../../etc -> deletes outside the cache
    return "cleared"
