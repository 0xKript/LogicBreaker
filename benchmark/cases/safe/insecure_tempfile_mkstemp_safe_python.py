import tempfile


def t():
    # SAFE look-alike: mkstemp() atomically creates the temp file and returns an
    # open fd + path -- no predictable-name/TOCTOU window. (mkstemp/mkdtemp/
    # NamedTemporaryFile/TemporaryFile/TemporaryDirectory are all safe.)
    fd, p = tempfile.mkstemp()
    return p
