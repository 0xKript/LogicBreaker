import ldap
from flask import Flask, request
app = Flask(__name__)

@app.route("/find")
def find():
    user = request.args.get("user")
    conn = ldap.initialize("ldap://x")
    # VULN: LDAP injection - filter built by concatenation
    return str(conn.search_s("dc=corp", ldap.SCOPE_SUBTREE, "(uid=" + user + ")"))
