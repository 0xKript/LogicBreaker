from flask import Flask
app = Flask(__name__)
# VULN: CSRF protection turned off globally
app.config["WTF_CSRF_ENABLED"] = False
