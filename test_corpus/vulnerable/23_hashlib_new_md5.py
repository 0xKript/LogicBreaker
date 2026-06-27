"""Vuln 23: hashlib.new("md5") -- algorithm as string arg."""
import hashlib

def hash_token(token: str) -> str:
    return hashlib.new("md5", token.encode()).hexdigest()
