from flask import Flask, request
app = Flask(__name__)

@app.route("/payroll", methods=["POST"])
def payroll():
    # SAFE: 'grant_amount' is a financial field, NOT a privilege role
    grant_amount = int(request.form.get("grant_amount"))
    if grant_amount <= 0:
        return "invalid", 400
    db.record_grant(grant_amount)
    return "ok"
