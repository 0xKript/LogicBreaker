# SAFE: the secrets module is a CSPRNG. Trap: this generates a security token,
# the exact place where random.random()/random.randint() would be insecure, but
# secrets.token_urlsafe is cryptographically strong.
import secrets
def issue_reset_token():
    return secrets.token_urlsafe(32)
