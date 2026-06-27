from flask import Flask, request
app = Flask(__name__)

@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    # VULN: Code injection - eval() on user input executes arbitrary Python
    return str(eval(expr))
