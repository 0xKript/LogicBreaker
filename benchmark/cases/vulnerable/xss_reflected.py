from flask import Flask, request
app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name")
    return "<html><body><h1>Hello " + name + "</h1></body></html>"
