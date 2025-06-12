import os
import requests
import openai

from flask import current_app

from db.db import db
from models import ApiConfig

# データベースからAPIキーを取得
def get_openai_key():
    config = db.session.query(ApiConfig).first()
    if config and config.secret_key:
        organization = config.organization_id if hasattr(config, "organization_id") else None
        return organization, config.secret_key
    raise ValueError("OpenAI APIキーが見つかりません")

def billing_openai():
    try:
        openai.api_key = get_openai_key()
        # ヘッダー情報を設定
        headers = {
            'Authorization': f'Bearer {openai.api_key}',
        }

        # クレジット残高を取得するエンドポイント
        url = 'https://api.openai.com/v1/dashboard/billing/credit_grants'

        # APIリクエストを送信
        response = requests.get(url, headers=headers)
        data_json = response.json()
        if response.status_code == 200:
            credit_balance = response.json().get('total_available', 0)
            print(f"Credit Balance: {credit_balance}")
            response.raise_for_status()
            # 'total_available'キーの有無をチェック
            if 'total_available' in data_json:
                return data_json['total_available']
            else:
                # logging.error("Key 'total_available' not found in response")
                return None
        else:
            print(f"Failed to retrieve credit balance: {response.status_code}, {response.text}")
    except requests.exceptions.RequestException as e:
        # logging.error(f"API request failed: {e}")
        return None

    return data_json['total_available']
