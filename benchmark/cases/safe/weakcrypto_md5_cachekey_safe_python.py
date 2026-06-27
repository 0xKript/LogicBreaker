import hashlib


def cache_key(filename):
    # SAFE look-alike: MD5 used purely as a non-security CACHE KEY for a file
    # (benign hint: cache/filename) -- not protecting any secret, so the
    # context-gated tier correctly stays silent.
    return "cache_" + hashlib.md5(filename.encode()).hexdigest()
