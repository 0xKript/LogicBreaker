# SAFE: argv list with shell=False (the default). Trap: user input is passed to a
# subprocess, which looks like command injection, but with a list + no shell the
# value is a single argv element and cannot break out into the shell.
import subprocess
from flask import request
def ping():
    host = request.args.get("host")
    return subprocess.check_output(["ping", "-c", "1", host], shell=False)
