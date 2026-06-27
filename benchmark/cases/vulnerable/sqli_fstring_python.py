# VULN: f-string interpolation of request data into SQL (no parameterization).
from flask import Flask, request
import sqlite3
app = Flask(__name__)

@app.route("/user")
def user():
    uid = request.args.get("id")
    con = sqlite3.connect("app.db")
    return str(con.execute(f"SELECT * FROM users WHERE id = {uid}").fetchall())
