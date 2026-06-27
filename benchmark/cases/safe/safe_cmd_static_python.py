# SAFE: a fixed administrative command with no user input. Trap: shell=True is
# present (the injection knob), but the command string is a constant literal, so
# there is no untrusted data to inject.
import subprocess
def restart_service():
    return subprocess.run("systemctl restart nginx", shell=True, check=True)
