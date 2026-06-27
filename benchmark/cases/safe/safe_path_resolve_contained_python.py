# SAFE: pathlib resolve() canonicalises the path, then a containment check keeps
# it under BASE. Trap: opens a user-supplied filename (path-traversal shape), but
# resolve() collapses any ../ and the prefix check rejects escapes.
from pathlib import Path
from flask import request, abort
BASE = Path("/srv/data").resolve()
def download():
    name = request.args.get("name", "")
    full = (BASE / name).resolve()
    if not str(full).startswith(str(BASE)):
        abort(403)
    return open(full, "rb").read()
