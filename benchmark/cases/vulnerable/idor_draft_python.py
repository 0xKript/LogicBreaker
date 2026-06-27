# VULN: any draft can be read by id with no ownership/authorization check (IDOR).
from flask import Flask, jsonify
from models import Post
app = Flask(__name__)

@app.route("/api/draft/<int:post_id>")
def get_draft(post_id):
    post = Post.query.get(post_id)
    return jsonify(title=post.title, content=post.content)
