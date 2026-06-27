import subprocess
def run_ping(host):
    # SAFE: argument list, no shell, no concatenation
    return subprocess.run(["ping", "-c", "1", host], capture_output=True)
