import ldap
from ldap.filter import escape_filter_chars
from flask import Flask, request
app = Flask(__name__)

@app.route("/find")
def find():
    user = request.args.get("user")
    conn = ldap.initialize("ldap://x")
    # SAFE: filter metacharacters escaped
    return str(conn.search_s("dc=corp", ldap.SCOPE_SUBTREE, "(uid=" + escape_filter_chars(user) + ")"))
