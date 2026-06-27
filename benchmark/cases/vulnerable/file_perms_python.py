import os

def save_upload(path, data):
    with open(path, "wb") as f:
        f.write(data)
    # VULN: world-writable file
    os.chmod(path, 0o777)
