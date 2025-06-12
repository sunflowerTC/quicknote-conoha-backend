from functools import wraps
from flask import session, jsonify

def login_required_api(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "ログインが必要です"}), 401
        return func(*args, **kwargs)
    return wrapper