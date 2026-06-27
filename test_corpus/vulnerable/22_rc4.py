"""Vuln 22: RC4 stream cipher."""
from Crypto.Cipher import ARC4

def encrypt_secret(secret: str, key: bytes) -> bytes:
    cipher = ARC4.new(key)
    return cipher.encrypt(secret.encode())
