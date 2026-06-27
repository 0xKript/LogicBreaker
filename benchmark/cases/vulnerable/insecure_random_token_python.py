# VULN: a password-reset token built from random.* (predictable, not a CSPRNG).
import random, string
def make_reset_token():
    token = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
    return token
