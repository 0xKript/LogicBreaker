# VULN: raw request value placed into a response header (CRLF / response split).
from flask import Flask, request, Response
app = Flask(__name__)

@app.route("/download")
def download():
    name = request.args.get("name")
    resp = Response("data")
    resp.headers.add("Content-Disposition", "attachment; filename=" + name)
    return resp
