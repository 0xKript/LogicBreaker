from flask import Flask, request, make_response
app = Flask(__name__)

@app.route("/setlang")
def setlang():
    lang = request.args.get("lang")
    resp = make_response("ok")
    # SAFE: CR/LF stripped from the header value
    resp.set_cookie("lang", lang.replace("\r", "").replace("\n", ""))
    return resp
