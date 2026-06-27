"""Vuln 21: DES encryption (always broken)."""
from Crypto.Cipher import DES

def encrypt_pin(pin: str, key: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pin.encode().ljust(8, b"\x00"))
