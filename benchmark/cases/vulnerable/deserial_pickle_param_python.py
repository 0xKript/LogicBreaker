# VULN: pickle.loads on a bare parameter -- RCE-class deserialization (CWE-502).
def load_session(data):
    import pickle
    return pickle.loads(data)
