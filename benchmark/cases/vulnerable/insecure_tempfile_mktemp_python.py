import tempfile


def t():
    # VULN: tempfile.mktemp() is race-prone (TOCTOU) and deprecated -- it only
    # returns a predictable path; the file is created non-atomically afterwards.
    return tempfile.mktemp()
