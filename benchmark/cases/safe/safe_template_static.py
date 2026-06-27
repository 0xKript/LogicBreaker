from flask import Flask, render_template
app = Flask(__name__)
@app.route("/home")
def home():
    # SAFE: static template name, no user input in template
    return render_template("home.html", title="Welcome")
