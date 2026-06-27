# VULN: parses untrusted XML with external entities enabled (XXE).
from lxml import etree
from flask import Flask, request
app = Flask(__name__)
@app.route("/xml", methods=["POST"])
def xml():
    parser = etree.XMLParser(resolve_entities=True)
    root = etree.fromstring(request.data, parser)
    return root.tag
