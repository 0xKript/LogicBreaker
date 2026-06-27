"""Vuln 06: SQL Injection via f-string."""
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/search")
def search():
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{name}%'")
    return str(cursor.fetchall())
