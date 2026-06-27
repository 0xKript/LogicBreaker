# SAFE: a plain file helper that opens exactly the path it is given -- no path is
# built by joining user input into a fixed directory, so this is not traversal.
def load(path):
    with open(path) as f:
        return f.read()
