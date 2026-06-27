# VULN: MD5 used to hash passwords (fast, broken -> trivial cracking).
import hashlib
def store_password(pw):
    digest = hashlib.md5(pw.encode()).hexdigest()
    return {"hash": digest}
