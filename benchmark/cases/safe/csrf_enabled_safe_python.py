from flask import Flask
from flask_wtf import CSRFProtect
app = Flask(__name__)
# SAFE: CSRF protection enabled
csrf = CSRFProtect(app)
