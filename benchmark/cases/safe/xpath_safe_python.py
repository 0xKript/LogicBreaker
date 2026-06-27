from lxml import etree
from flask import Flask, request
app = Flask(__name__)
tree = etree.parse("users.xml")

@app.route("/lookup")
def lookup():
    name = request.args.get("name")
    # SAFE: parameterized XPath with a bound variable
    return str(tree.xpath("//user[username=$n]/role/text()", n=name))
