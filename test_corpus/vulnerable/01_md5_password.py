"""Vuln 01: MD5 password hashing (the user's exact example)."""
import hashlib

def hash_password(pw: str) -> str:
    return hashlib.md5(pw.encode()).hexdigest()

def verify_password(pw: str, stored: str) -> bool:
    return hash_password(pw) == stored
