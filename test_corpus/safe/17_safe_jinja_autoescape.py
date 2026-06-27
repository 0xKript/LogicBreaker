"""Adversarial safe: XSS prevented via Jinja2 autoescape (default)."""
from flask import Flask, request, render_template_string

app = Flask(__name__)
# Flask's render_template_string autoescapes by default

@app.route("/welcome")
def welcome():
    user = request.args.get("user", "")
    # autoescape is ON -> safe even with user input
    return render_template_string("<h1>Welcome {{ user }}</h1>", user=user)
