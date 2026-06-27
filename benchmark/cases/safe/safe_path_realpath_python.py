# SAFE: realpath + basename + a fixed root. Trap: a user-supplied filename is
# opened, which looks like path traversal, but basename() strips directory parts
# and the realpath is asserted to stay under the allowed base.
import os
from flask import request, abort
BASE = "/srv/reports"
def download():
    name = os.path.basename(request.args.get("name", ""))
    full = os.path.realpath(os.path.join(BASE, name))
    if not full.startswith(BASE + os.sep):
        abort(403)
    return open(full, "rb").read()
