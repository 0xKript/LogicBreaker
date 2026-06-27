# SAFE: sqlite3 "?" placeholders. Trap: an f-string appears on the next line and
# looks like it builds the query, but it is only a log message; the query itself
# is fully parameterized.
import sqlite3, logging
from flask import request
def find(conn):
    name = request.args.get("name")
    logging.info(f"lookup for {name}")
    return conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()
