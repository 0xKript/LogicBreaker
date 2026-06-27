"""Vuln 05: SQL Injection via string concatenation."""
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/users")
def get_user():
    user_id = request.args.get("id", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return str(cursor.fetchall())
