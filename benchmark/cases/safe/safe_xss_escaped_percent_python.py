# SAFE: request value is HTML-escaped before %-formatting into the page.
from flask import Flask, request
import markupsafe
app = Flask(__name__)
@app.route("/hi")
def hi():
    name = request.args.get("name")
    return "<h1>Hello %s</h1>" % markupsafe.escape(name)
