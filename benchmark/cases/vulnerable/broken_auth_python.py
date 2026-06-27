from flask import Flask, request
app = Flask(__name__)
@app.route("/promote", methods=["POST"])
def promote():
    # VULN: trusts client-supplied role
    if request.form.get("is_admin") == "true":
        grant_admin()
    return "ok"
