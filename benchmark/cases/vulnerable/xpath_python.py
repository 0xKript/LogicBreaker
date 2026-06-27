from lxml import etree
from flask import Flask, request
app = Flask(__name__)
tree = etree.parse("users.xml")

@app.route("/lookup")
def lookup():
    name = request.args.get("name")
    # VULN: XPath injection - input concatenated into the expression
    return str(tree.xpath("//user[username='" + name + "']/role/text()"))
