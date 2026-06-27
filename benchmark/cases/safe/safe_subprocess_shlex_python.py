# SAFE: the host is quoted with shlex.quote before being placed in a shell string.
# Trap: shell=True with user input is the command-injection shape, but the
# quoting makes the value a single inert argument.
import subprocess, shlex
from flask import request
def ping():
    host = shlex.quote(request.args.get("host", ""))
    return subprocess.check_output("ping -c 1 " + host, shell=True)
