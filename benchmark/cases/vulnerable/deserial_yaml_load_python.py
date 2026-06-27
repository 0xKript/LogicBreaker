# VULN: yaml.load (FullLoader/unsafe) on request data.
import yaml
from flask import Flask, request
app = Flask(__name__)

@app.route("/import", methods=["POST"])
def imp():
    data = yaml.load(request.data, Loader=yaml.Loader)   # arbitrary object construction
    return str(data)
