"""Vuln 18: Weak randomness for OTP."""
import random

def generate_otp():
    return str(random.randint(100000, 999999))

def generate_session_token():
    return "".join(str(random.randint(0, 9)) for _ in range(32))
