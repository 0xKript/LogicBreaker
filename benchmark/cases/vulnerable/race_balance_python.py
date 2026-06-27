from flask import Flask, request, session
app = Flask(__name__)

@app.route("/withdraw", methods=["POST"])
def withdraw():
    amount = int(request.form.get("amount"))
    balance = get_balance(session["uid"])
    # VULN: TOCTOU - check then act on balance with a DB round-trip in between,
    # write-back via a setter, no lock / atomic update
    if balance >= amount:
        db.execute("INSERT INTO ledger VALUES (?)", (amount,))
        set_balance(session["uid"], balance - amount)
    return "ok"
