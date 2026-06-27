"""Vuln 19: Insecure temp file via mktemp."""
import tempfile

def get_temp_path():
    path = tempfile.mktemp()
    with open(path, "w") as f:
        f.write("session data")
    return path
