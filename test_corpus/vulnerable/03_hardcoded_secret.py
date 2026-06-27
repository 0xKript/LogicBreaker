"""Vuln 03: Hardcoded API key + secret."""
API_KEY = "sk-live-abc123def456ghi789jkl012mno345pqr678"
JWT_SECRET = "my_super_secret_jwt_key_2024"
DB_PASSWORD = "admin123"

def get_client():
    return {"api_key": API_KEY, "secret": JWT_SECRET}
