import sqlite3
def get_all_users(conn):
    # SAFE: constant query, no user input
    return conn.execute("SELECT * FROM users WHERE active = 1").fetchall()
