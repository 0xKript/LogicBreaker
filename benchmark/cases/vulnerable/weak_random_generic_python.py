# VULN: non-cryptographic PRNG used to produce a value (CWE-330, Bandit B311).
import random
def pick_id():
    return random.randint(1000, 9999)
