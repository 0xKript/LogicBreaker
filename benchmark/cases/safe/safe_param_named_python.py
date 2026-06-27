# SAFE: psycopg2 named parameters. Trap: the "%(uid)s" looks like %-formatting
# (classic SQLi), but it is a BOUND placeholder filled by the driver, not Python
# string interpolation -- the value never touches the SQL text.
import psycopg2
from flask import request
def get_user(conn):
    uid = request.args.get("uid")
    cur = conn.cursor()
    cur.execute("SELECT email FROM users WHERE id = %(uid)s", {"uid": uid})
    return cur.fetchone()
