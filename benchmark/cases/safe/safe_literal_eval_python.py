# SAFE: ast.literal_eval only parses literals, not code.
import ast
def parse_value(s):
    return ast.literal_eval(s)
