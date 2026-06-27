# VULN: user input concatenated into a rendered template (reflected XSS).
from flask import Flask, request, render_template_string
app = Flask(__name__)
@app.route("/hi")
def hi():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hi " + name + "</h1>")
