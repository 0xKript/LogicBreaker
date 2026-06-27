import ast
from flask import Flask, request
app = Flask(__name__)

@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    # SAFE: literal_eval parses only literals, cannot execute code
    return str(ast.literal_eval(expr))
