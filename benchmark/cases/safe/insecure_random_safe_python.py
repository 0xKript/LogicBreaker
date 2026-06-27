import secrets
from flask import Flask
app = Flask(__name__)

def generate_reset_token(user):
    # SAFE: cryptographically secure RNG
    reset_token = secrets.token_urlsafe(16)
    return reset_token
