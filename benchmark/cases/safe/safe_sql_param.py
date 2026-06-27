from flask import Flask, request, jsonify
import sqlite3
app = Flask(__name__)

@app.route("/user")
def get_user():
    name = request.args.get("name")
    conn = sqlite3.connect("db")
    # SAFE: parameterized query
    row = conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()
    return jsonify(row)
