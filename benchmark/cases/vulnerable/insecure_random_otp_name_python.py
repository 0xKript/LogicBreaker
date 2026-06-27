import random


def otp():
    # VULN: predictable RNG used for a one-time password. The security context is
    # in the FUNCTION NAME (otp), not on the same line as the random call, so a
    # proximity-only check misses it.
    code = random.randint(100000, 999999)
    return str(code)
