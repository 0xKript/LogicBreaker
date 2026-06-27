import random
from flask import Flask
app = Flask(__name__)

def generate_reset_token(user):
    # VULN: predictable RNG for a security token
    reset_token = "".join(str(random.randint(0, 9)) for _ in range(6))
    return reset_token
