"""Adversarial: looks like SQLi but uses parameterized query -- safe."""
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/users")
def get_user():
    user_id = request.args.get("id", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # the %s here is a Python format spec, NOT a SQL placeholder -- but the
    # query is parameterized via the (?,) tuple. The matcher must see the
    # parameterisation and NOT flag.
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return str(cursor.fetchall())
