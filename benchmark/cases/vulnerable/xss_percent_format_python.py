from flask import Flask, request
app = Flask(__name__)


@app.route("/hello")
def hello():
    # VULN: reflected XSS via printf-style % formatting -- the request value is
    # written into an HTML response with no escaping.
    return "<h1>Hello %s</h1>" % request.args.get("name", "")
