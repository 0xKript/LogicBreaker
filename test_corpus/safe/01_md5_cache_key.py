"""Safe 01: MD5 used for a cache key (legitimate)."""
import hashlib

def cache_key(filename: str) -> str:
    return hashlib.md5(filename.encode()).hexdigest()[:16]
