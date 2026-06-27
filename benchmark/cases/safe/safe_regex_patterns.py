import re
# SAFE: these are detection regexes, not vulnerabilities
SQL_PATTERN = re.compile(r"SELECT .* FROM .* WHERE")
CMD_PATTERN = re.compile(r"os\.system\(")
def detect(code):
    return bool(SQL_PATTERN.search(code))
