# SAFE: the resolved address must be global (not private/loopback) before fetch.
# Trap: it fetches a user URL (SSRF shape), but the IP check blocks internal and
# cloud-metadata targets.
import socket, ipaddress, requests
from urllib.parse import urlparse
from flask import request, abort
def fetch():
    url = request.args.get("url", "")
    host = urlparse(url).hostname
    ip = ipaddress.ip_address(socket.gethostbyname(host))
    if not ip.is_global:
        abort(400)
    return requests.get(url, timeout=5).text
