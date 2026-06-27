# SAFE: an SSL context with certificate verification required. Trap: it builds a
# custom ssl context (where CERT_NONE would disable validation), but this one
# enforces CERT_REQUIRED with hostname checking.
import ssl, socket
def secure_socket(host):
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx.wrap_socket(socket.socket(), server_hostname=host)
