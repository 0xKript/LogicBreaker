# VULN: path traversal -- a parameter is joined into a fixed directory and opened (CWE-22).
def read_user_file(filename):
    with open("/var/data/" + filename) as f:
        return f.read()
