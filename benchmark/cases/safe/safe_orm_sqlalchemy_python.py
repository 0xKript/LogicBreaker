# SAFE: SQLAlchemy ORM. Trap: .filter() with a comparison looks like a raw query,
# but the ORM compiles it to a bound parameter; no string concatenation occurs.
from models import Session, User
from flask import request
def search():
    email = request.args.get("email")
    return Session().query(User).filter(User.email == email).all()
