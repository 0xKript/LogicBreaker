from flask import Flask, request, make_response
app = Flask(__name__)

@app.route("/setlang")
def setlang():
    lang = request.args.get("lang")
    resp = make_response("ok")
    # VULN: CRLF / response-splitting - raw input in a response header
    resp.set_cookie("lang", lang)
    return resp
