import markupsafe
from flask import Flask, request
app = Flask(__name__)


@app.route("/hello")
def hello():
    # SAFE look-alike: same %-format HTML shape, but the request value is
    # HTML-escaped before formatting, so no markup can be injected.
    return "<h1>%s</h1>" % markupsafe.escape(request.args.get("name", ""))
