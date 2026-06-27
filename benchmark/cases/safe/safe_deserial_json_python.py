# SAFE: json.loads only produces dicts/lists/scalars. Trap: it deserialises an
# untrusted cookie (the spot where pickle.loads would be an RCE), but JSON has no
# object-construction semantics, so there is no gadget.
import json
from flask import request
def prefs():
    raw = request.cookies.get("prefs", "{}")
    return json.loads(raw)
