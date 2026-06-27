"""Vuln 12: SSTI via render_template_string."""
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    template = "<h1>Hello " + name + "</h1>"
    return render_template_string(template)
