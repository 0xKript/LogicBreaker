from flask import Flask, request
from markupsafe import escape
app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name")
    return "<html><body><h1>Hello " + escape(name) + "</h1></body></html>"
