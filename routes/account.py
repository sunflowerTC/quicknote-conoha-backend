from flask import Blueprint, request, jsonify
from db.db import db
from models import Account
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import SQLAlchemyError

from decorators import login_required_api

account_bp = Blueprint('account', __name__, url_prefix='/api/account')

# 🔵 アカウントの作成
@account_bp.route('/', methods=['POST'])
@login_required_api
def create_accounts():
    try:
        data = request.json
        
        # 🔵 データのバリデーション
        required_fields = ['email', 'userid', 'password', 'totp_secret', 'role', 'last_name', 'first_name']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'{field} is required'}), 400

        # 🔵 Email フォーマットの確認
        if '@' not in data['email']:
            return jsonify({'error': 'Invalid email format'}), 400
        
        # 🔵 パスワードのハッシュ化
        hashed_password = generate_password_hash(data['password'])
        
        # 🔵 アカウント作成
        new_account = Account(
            email=data['email'],
            userid=data['userid'],
            password_hash=hashed_password,  # ✅ ハッシュ化されたパスワードを保存
            totp_secret=data['totp_secret'],
            role=data['role'],
            last_name=data['last_name'],
            first_name=data['first_name']
        )
        db.session.add(new_account)
        db.session.commit()
        return jsonify({'message': 'Account created successfully'}), 201

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': 'Database error', 'details': str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'An unexpected error occurred', 'details': str(e)}), 500


# 🔵 アカウント一覧の取得
@account_bp.route('/', methods=['GET'])
@login_required_api
def get_accounts():
    try:
        accounts = Account.query.all()
        accounts_list = [{
            'id': account.id,
            'email': account.email,
            'userid': account.userid,
            'role': account.role,
            'last_name': account.last_name,
            'first_name': account.first_name
        } for account in accounts]
        return jsonify(accounts_list), 200

    except Exception as e:
        return jsonify({'error': 'Failed to get accounts', 'details': str(e)}), 500

