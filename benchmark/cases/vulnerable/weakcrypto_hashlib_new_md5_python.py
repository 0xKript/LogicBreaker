import hashlib


def hash_password(password):
    # VULN: MD5 (via hashlib.new with a string algorithm) used on a password --
    # context-gated tier: weak hash + a security subject (password) nearby.
    return hashlib.new("md5", password.encode()).hexdigest()
