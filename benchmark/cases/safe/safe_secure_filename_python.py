# SAFE: werkzeug secure_filename strips path components. Trap: a user-supplied
# upload name is joined to a directory (path-traversal shape), but the
# sanitiser removes "../" and separators.
import os
from werkzeug.utils import secure_filename
from flask import request
UP = "/srv/uploads"
def upload():
    f = request.files["file"]
    name = secure_filename(f.filename)
    f.save(os.path.join(UP, name))
    return "ok"
