# VULN: real, high-entropy provider secrets committed in source.
import requests

api_key = "TESTKEY_9aXcVbNm2hJ4Kd6Ys1pQrStUvWxYz0123"
STRIPE_SECRET = "TESTSECRET_51H8xQ2eZvKYlo2Ck9mN3pQrStUvWxYz0123"

def charge():
    return requests.post(
        "https://api.stripe.com/v1/charges",
        headers={"Authorization": "Bearer " + STRIPE_SECRET},
        params={"key": api_key},
    )
