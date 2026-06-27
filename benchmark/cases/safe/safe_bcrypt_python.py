# SAFE: bcrypt is a slow, salted password hash. Trap: this is password hashing
# (the exact place md5/sha1 would be weak), but bcrypt is the correct primitive.
import bcrypt
def store_password(pw: str):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12))
