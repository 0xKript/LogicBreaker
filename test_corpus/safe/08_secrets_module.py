"""Safe 08: secrets module for tokens (correct CSPRNG)."""
import secrets

def generate_otp() -> str:
    return str(secrets.randbelow(900000) + 100000)

def generate_session_token() -> str:
    return secrets.token_urlsafe(32)
