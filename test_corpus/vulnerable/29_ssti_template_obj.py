"""Hidden: SSTI via Jinja2 Template object with user input."""
from flask import Flask, request
from jinja2 import Template

app = Flask(__name__)

@app.route("/render")
def render():
    user_input = request.args.get("name", "")
    t = Template("Hello " + user_input)
    return t.render()
