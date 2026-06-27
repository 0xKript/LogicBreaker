import threading
from flask import Flask, request, session, abort
app = Flask(__name__)
_lock = threading.Lock()

@app.route("/withdraw", methods=["POST"])
def withdraw():
    amount = int(request.form.get("amount"))
    if amount <= 0:
        abort(400)
    # SAFE: the check-and-update is held under a lock (no time-of-use gap)
    with _lock:
        balance = get_balance(session["uid"])
        if balance >= amount:
            db.execute("INSERT INTO ledger VALUES (?)", (amount,))
            set_balance(session["uid"], balance - amount)
    return "ok"
