# VULN: tainted input flows through a helper that builds the query string, then
# into the SQL sink (interprocedural data flow, no concat at the sink site).
import sqlite3
from flask import Flask, request
app = Flask(__name__)

def build_lookup(term):
    return "SELECT * FROM products WHERE name = '" + term + "'"

@app.route("/search")
def search():
    q = build_lookup(request.args.get("term"))
    return str(sqlite3.connect("shop.db").execute(q).fetchall())
