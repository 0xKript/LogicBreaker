"""Vuln 02: SHA1 password hashing."""
import hashlib

def make_token(secret: str) -> str:
    return hashlib.sha1(secret.encode()).hexdigest()

def make_signature(payload: str, key: str) -> str:
    return hashlib.sha1((payload + key).encode()).hexdigest()
