# SAFE: PBKDF2-HMAC-SHA256 with a high iteration count. Trap: it calls into
# hashlib (where a bare md5 would be insecure), but this is a proper KDF.
import hashlib, os
def derive(pw: str):
    salt = os.urandom(16)
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 600_000)
