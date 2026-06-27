# SAFE: itsdangerous verifies a signature before loading JSON data. Trap: it
# deserialises a client token (the pickle-RCE spot), but the value is signature
# checked and JSON-only, so it cannot construct arbitrary objects.
from itsdangerous import URLSafeTimedSerializer, BadSignature
from flask import request, abort
s = URLSafeTimedSerializer("server-secret")
def load_session():
    try:
        return s.loads(request.cookies.get("session", ""), max_age=3600)
    except BadSignature:
        abort(400)
