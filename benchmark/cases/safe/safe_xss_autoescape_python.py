# SAFE: Jinja2 render_template autoescapes by default. Trap: user input is passed
# into a template (reflected-XSS shape), but template autoescaping encodes HTML
# metacharacters; this is render_template (a file), not render_template_string.
from flask import Flask, request, render_template
app = Flask(__name__)
@app.route("/profile")
def profile():
    return render_template("profile.html", name=request.args.get("name", ""))
