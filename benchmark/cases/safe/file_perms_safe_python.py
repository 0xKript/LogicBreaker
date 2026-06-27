import os

def save_upload(path, data):
    with open(path, "wb") as f:
        f.write(data)
    # SAFE: owner-only read/write
    os.chmod(path, 0o600)
