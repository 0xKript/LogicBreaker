# SAFE: only a fixed set of internal paths is allowed. Trap: the redirect target
# comes from the request (open-redirect shape), but anything not on the allow-list
# falls back to "/".
from flask import request, redirect
ALLOWED = {"/dashboard", "/profile", "/settings"}
def after_login():
    nxt = request.args.get("next", "/")
    return redirect(nxt if nxt in ALLOWED else "/")
