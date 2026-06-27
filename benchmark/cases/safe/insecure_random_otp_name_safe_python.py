import secrets


def otp():
    # SAFE look-alike: same security-denoting function name (otp), but a
    # cryptographically secure RNG (secrets) is used -- not the predictable
    # `random` module.
    code = secrets.randbelow(900000) + 100000
    return str(code)
