"""Safe 02: bcrypt password hashing (correct)."""
import bcrypt

def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verify_password(pw: str, stored: str) -> bool:
    return bcrypt.checkpw(pw.encode(), stored.encode())
