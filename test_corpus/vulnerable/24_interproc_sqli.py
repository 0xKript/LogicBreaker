"""Hidden: interprocedural SQL injection -- taint flows through a helper."""
from flask import Flask, request
import sqlite3

app = Flask(__name__)

def build_query(user_input):
    return "SELECT * FROM users WHERE name = '" + user_input + "'"

@app.route("/search")
def search():
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    q = build_query(name)
    cursor.execute(q)
    return str(cursor.fetchall())
