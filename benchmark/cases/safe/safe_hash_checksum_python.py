# SAFE: SHA-256 used for file integrity (a checksum), not passwords. Trap: it
# calls hashlib (where md5/sha1 on a password would be weak), but SHA-256 for a
# content checksum is the correct, collision-resistant choice.
import hashlib
def file_checksum(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()
