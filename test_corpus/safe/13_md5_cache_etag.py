"""Adversarial: MD5 used for cache key -- must NOT be flagged (benign use)."""
import hashlib

def cache_key(filename: str) -> str:
    # MD5 here is for a CACHE KEY (etag-like), not security -- safe
    return "cache_" + hashlib.md5(filename.encode()).hexdigest()[:8]

def etag_for(content: bytes) -> str:
    return 'W/"' + hashlib.md5(content).hexdigest() + '"'
