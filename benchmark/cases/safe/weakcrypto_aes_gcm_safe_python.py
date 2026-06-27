from Crypto.Cipher import AES


def enc(d, key, nonce):
    # SAFE look-alike: AES in GCM mode is an authenticated, modern cipher. Proves
    # the always-broken tier flags only ECB/DES/RC4 -- not a strong AES mode.
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.encrypt_and_digest(d)
