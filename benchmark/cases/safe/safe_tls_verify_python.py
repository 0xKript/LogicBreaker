# SAFE: certificate verification is explicitly enabled. Trap: the verify keyword
# is present (the knob that becomes dangerous as verify=False), but here it is
# True, so the TLS chain is validated.
import requests
def call_api(token):
    return requests.get("https://api.example.com/me",
                        headers={"Authorization": "Bearer " + token},
                        verify=True)
