"""Vuln 08: Code Injection via eval."""
from flask import Flask, request

app = Flask(__name__)

@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    return str(eval(expr))
