# SAFE: the id is validated against a strict pattern before use. Trap: a request
# value is interpolated into a path, but the regex guarantees it is digits only.
import re, os
from flask import request, abort
def report():
    rid = request.args.get("id", "")
    if not re.fullmatch(r"\d{1,9}", rid):
        abort(400)
    return open(os.path.join("/srv/reports", rid + ".txt")).read()
