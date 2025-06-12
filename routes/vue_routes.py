# backend/routes/vue_routes.py
import os
from flask import Blueprint, send_from_directory, jsonify

vue_bp = Blueprint("vue", __name__)

@vue_bp.route("/", defaults={"path": ""})
@vue_bp.route("/<path:path>")
def serve_vue(path):
    if path.startswith("api"):
        return jsonify({"error": "Not Found"}), 404

    dist_dir = os.path.join(os.path.dirname(__file__), "../../frontend/dist")
    file_path = os.path.join(dist_dir, path)

    if os.path.exists(file_path):
        return send_from_directory(dist_dir, path)
    else:
        return send_from_directory(dist_dir, "index.html")
