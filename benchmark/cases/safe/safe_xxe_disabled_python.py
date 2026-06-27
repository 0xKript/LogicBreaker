# SAFE: uses defusedxml, which disables external entities / DTDs entirely.
from defusedxml.ElementTree import fromstring
from flask import Flask, request
app = Flask(__name__)

@app.route("/upload", methods=["POST"])
def upload():
    root = fromstring(request.data)     # defusedxml -> XXE-safe
    return root.tag
