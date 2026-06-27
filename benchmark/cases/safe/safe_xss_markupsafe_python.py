# SAFE: markupsafe.escape neutralises HTML metacharacters. Trap: user input is
# placed into an HTML response (reflected XSS shape), but escaping converts
# <, >, & into entities before output.
from markupsafe import escape
from flask import request
def greet():
    name = request.args.get("name", "")
    return "<h1>Hello " + str(escape(name)) + "</h1>"
