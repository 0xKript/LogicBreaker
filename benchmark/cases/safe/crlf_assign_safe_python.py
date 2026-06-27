from flask import Flask, request, make_response
app = Flask(__name__)

@app.route("/track")
def track():
    ref = request.args.get("ref")
    resp = make_response("ok")
    # SAFE: CR/LF stripped before writing the header
    resp.headers["X-Referrer"] = ref.replace("\r", "").replace("\n", "")
    return resp
