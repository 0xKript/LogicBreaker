from flask import Flask, jsonify, abort, g
app = Flask(__name__)

@app.route("/invoice/<invoice_id>")
def get_invoice(invoice_id):
    inv = Invoice.query.get(invoice_id)
    # SAFE: object scope field compared against the authenticated principal
    if inv.tenant_id != g.tenant_id:
        abort(404)
    return jsonify(inv.to_dict())
