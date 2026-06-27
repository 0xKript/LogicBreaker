# SAFE: the token is verified with a fixed algorithm and signature check. Trap:
# jwt.decode is the sink that becomes a bypass with verify=False or alg "none",
# but here algorithms is pinned and verification is on.
import jwt
def whoami(token, key):
    return jwt.decode(token, key, algorithms=["HS256"],
                      options={"verify_signature": True})
