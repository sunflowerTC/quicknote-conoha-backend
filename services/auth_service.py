from db.db import db
from models import UserToken

from zoneinfo import ZoneInfo
from datetime import datetime, timedelta
import requests

from flask import current_app
import msal

import utils

import logging
from logging_config import setup_logging

"""IPアドレスを取得"""
server_ip = utils.get_local_ip() or "Unknown IP"

"""ロギングのセットアップ"""
setup_logging(server_ip)

"""ログファイル設定"""
logger = logging.getLogger("mailsystem")

"""ユーザーのアクセストークン・リフレッシュトークンをDBに保存"""
def save_user_tokens_to_db(user_id, access_token, refresh_token, expires_in=None):
    token_record = db.session.query(UserToken).filter_by(user_id=user_id).first()
    
    now = datetime.now(tz=ZoneInfo("Asia/Tokyo"))
    expires_at = now + timedelta(seconds=expires_in) if expires_in else None

    if token_record:
        token_record.access_token = access_token
        token_record.refresh_token = refresh_token
        token_record.updated_at = now
        if expires_at:
            token_record.expires_at = expires_at
    else:
        token_record = UserToken(
            user_id=user_id,
            access_token=access_token,
            refresh_token=refresh_token,
            created_at=datetime.utcnow(),
            updated_at=now,
            expires_at=expires_at
        )
        db.session.add(token_record)

    db.session.commit()

"""DBサーバーからユーザーのアクセストークンを取得し、必要に応じてリフレッシュ"""
def get_valid_access_token(graph_user_id):
    token = db.session.query(UserToken).filter_by(user_id=graph_user_id).first()
    # logger.info(f"token: {token.access_token}")
    # logger.info(f"refresh_token: {token.refresh_token}")

    if not token:
        raise Exception("ユーザーのトークン情報が見つかりません")

    # 現在の access_token の有効性を Graph API で検証
    response = requests.get(
        "https://graph.microsoft.com/v1.0/me",
        headers={"Authorization": f"Bearer {token.access_token}"}
    )

    if response.status_code == 200:
        logger.info("✅ access_token は有効です")
        return token.access_token

    elif response.status_code == 401 and token.refresh_token:
        logger.warning("⚠️ access_token が期限切れ。refresh_token による再取得を試みます")
        # トークンの再取得（リフレッシュ）
        msal_app = current_app.config.get("MSAL_APP")
        scopes = current_app.config.get("MS_SCOPES")
        user_scopes = current_app.config.get("MS_USER_SCOPES")

        result = msal_app.acquire_token_by_refresh_token(token.refresh_token, scopes=scopes)

        logger.info(f"📥 refresh_token による取得結果: {result}")

        if "access_token" in result:
            new_access_token = result["access_token"]
            new_refresh_token = result.get("refresh_token", token.refresh_token)
            expires_in = result.get("expires_in", 3600)

            # DBの更新
            save_user_tokens_to_db(graph_user_id, new_access_token, new_refresh_token, expires_in)
            logger.info("✅ 新しい access_token を返却")

            return new_access_token
        else:
            logger.error(f"❌ アクセストークンのリフレッシュに失敗: {result.get('error_description', '不明')}")
            raise Exception("アクセストークンのリフレッシュに失敗しました")

    else:
        logger.error(f"❌ アクセストークン検証エラー: {response.status_code}, {response.text}")
        raise Exception(f"アクセストークン確認中にエラー: {response.status_code}, {response.text}")
