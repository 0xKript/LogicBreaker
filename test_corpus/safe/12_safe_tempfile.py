"""Safe 12: tempfile.mkstemp (correct, race-free)."""
import tempfile
import os

def get_temp_path():
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, "w") as f:
        f.write("session data")
    return path
