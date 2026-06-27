# SAFE: secrets is a CSPRNG; no use of the weak random module at all.
import secrets
def make_token():
    return secrets.token_hex(16)
