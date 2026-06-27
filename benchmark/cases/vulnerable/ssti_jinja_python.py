# VULN: untrusted input used as the template itself (SSTI -> RCE in Jinja2).
from flask import Flask, request, render_template_string
app = Flask(__name__)
@app.route("/render")
def render():
    tpl = request.args.get("tpl", "")
    return render_template_string(tpl)
