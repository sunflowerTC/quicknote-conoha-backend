from flask import Blueprint, jsonify
import utils
import requests

graph_bp = Blueprint("graph_bp", __name__)

@graph_bp.route("/api/graph/subscriptions", methods=["GET"])
def get_graph_subscriptions():
    access_token = utils.create_access_token()
    if not access_token:
        return jsonify({"error": "アクセストークン取得失敗"}), 500

    headers = {"Authorization": f"Bearer {access_token}"}
    res = requests.get("https://graph.microsoft.com/v1.0/subscriptions", headers=headers)

    if res.status_code == 200:
        return jsonify(res.json())
    else:
        return jsonify({"error": "取得失敗", "status": res.status_code, "response": res.text}), 500