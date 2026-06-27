from flask import Flask, jsonify
app = Flask(__name__)

@app.route("/invoice/<invoice_id>")
def get_invoice(invoice_id):
    # VULN: IDOR - fetch by client id with NO ownership check (filter_by id only)
    inv = Invoice.query.filter_by(id=invoice_id).first()
    return jsonify(inv.to_dict())
