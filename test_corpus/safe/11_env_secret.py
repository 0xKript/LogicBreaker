"""Safe 11: API key loaded from env (correct)."""
import os
API_KEY = os.environ.get("API_KEY")
JWT_SECRET = os.environ.get("JWT_SECRET")

def get_client():
    if not API_KEY:
        raise RuntimeError("API_KEY not configured")
    return {"api_key": API_KEY, "secret": JWT_SECRET}
