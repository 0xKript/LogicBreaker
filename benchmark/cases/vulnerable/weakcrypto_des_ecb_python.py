from Crypto.Cipher import DES


def enc(d, k):
    # VULN: DES in ECB mode -- an always-broken primitive. Note there is NO
    # security keyword nearby, yet it must still be flagged (always-broken tier).
    cipher = DES.new(k, DES.MODE_ECB)
    return cipher.encrypt(d)
