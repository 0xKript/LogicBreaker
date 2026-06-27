# VULN: eval on a bare parameter -- arbitrary code execution (CWE-94).
def run_expr(user_code):
    return eval(user_code)
