from flask import Flask, request, make_response
app = Flask(__name__)

@app.route("/track")
def track():
    ref = request.args.get("ref")
    resp = make_response("ok")
    # VULN: CRLF via header ASSIGNMENT (not a call) - raw input in a header
    resp.headers["X-Referrer"] = ref
    return resp
