# SAFE: eval of a constant literal -- nothing attacker-controlled.
def compute():
    return eval("1 + 2")
