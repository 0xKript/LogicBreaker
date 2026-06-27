# SAFE: this file only TALKS about vulnerabilities in comments/docstrings.
def sanitize(value):
    """Prevents SQL injection by escaping. Avoids os.system command injection.
    Blocks path traversal like ../etc/passwd. No pickle.loads here."""
    return value.replace("'", "''")
