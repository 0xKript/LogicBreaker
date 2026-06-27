from Crypto.Cipher import ARC4


def enc(d, key):
    # VULN: RC4/ARC4 is a broken stream cipher -- always-broken tier (no nearby
    # security keyword required).
    cipher = ARC4.new(key)
    return cipher.encrypt(d)
