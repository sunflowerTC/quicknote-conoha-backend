import os
import requests
import json

from flask import current_app, session

from db.db import db
from models import Account, Job, ApiConfig

from datetime import datetime, timedelta, timezone
import pytz

from flask import request, jsonify

import socket
import logging
from logging_config import setup_logging

from dotenv import load_dotenv
import base64

import msal

import openai
from openai import OpenAI

import pyotp
import qrcode
import io

import jwt
import time

"""mailsystem.envファイルを読み込む"""
load_dotenv("mailsystem.env")

"""ログファイル設定"""
logger = logging.getLogger("mailsystem")

"""ローカルIPアドレスを取得する関数"""
def get_local_ip():
    try:
        # 外向きのUDP接続を一時的に張る（GoogleのDNS 8.8.8.8 に接続するが、実際に通信は発生しない）
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        logger.error("ローカル IP アドレスの取得に失敗しました: %s", e)
        return None

"""IPアドレスを取得する関数"""
def get_global_ip():
    try:
        response = requests.get('https://httpbin.org/ip')
        response.raise_for_status()
        return response.json()['origin']
    except requests.RequestException as e:
        logger.error("IPアドレスの取得に失敗しました: %s", e)
        return None

"""現在の日時を取得"""
def current_date():
    now_date = datetime.now()
    formatted_day_time = now_date.strftime('%Y-%m-%d %H:%M:%S')

    return now_date, formatted_day_time

"""ISO 8601形式に変換"""
def conversion_iso(date_time):
    formats = ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S']  # 対応するフォーマットをリスト化
    for fmt in formats:
        try:
            dt = datetime.strptime(date_time, fmt)
            date_time_iso = dt.strftime('%Y-%m-%dT%H:%M:%SZ')  # ISO 8601形式に変換
            logger.info(f'ISO形式のメール処理開始日時: {date_time_iso}')
            return date_time_iso
        except ValueError:
            continue
    # すべてのフォーマットで失敗した場合
    logger.error(f'日付の変換エラー: {date_time}')
    return jsonify({'error': 'Invalid date format'}), 400

"""タイムゾーンを変換"""
def convert_to_japan_time(utc_time_str):
    # ISO 8601形式の日時をパース
    utc_time = datetime.strptime(utc_time_str, "%Y-%m-%dT%H:%M:%SZ")
    
    # UTCタイムゾーンを設定
    utc_time = utc_time.replace(tzinfo=pytz.UTC)
    
    # 日本時間に変換
    japan_time = utc_time.astimezone(pytz.timezone("Asia/Tokyo"))
    return japan_time.strftime("%Y-%m-%d %H:%M:%S")  # 必要に応じてフォーマット調整

"""TOTP_SECRETを生成"""
def get_totp_qr(email, totp_secret):
    """Google Authenticator 用の QR コードを生成"""
    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
        name=email,
        issuer_name="QuickNote"
    )

    # QRコードの生成
    qr = qrcode.make(totp_uri)
    buffer = io.BytesIO()
    qr.save(buffer, format='PNG')
    buffer.seek(0)

    # QRコードを Base64 エンコードして返す
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{qr_base64}"

"""TOTPを検証"""
def verify_totp():
    data = request.json
    otp = data.get('totp')

    # 🔵 TOTP_SECRET を使用して TOTP インスタンスを生成
    totp = pyotp.TOTP(TOTP_SECRET)

    # 🔵 ワンタイムパスワードの検証
    if totp.verify(otp):
        return jsonify({"success": True, "message": "TOTP 検証成功"})
    else:
        return jsonify({"success": False, "message": "TOTP 検証失敗"}), 401

"""JSONファイルの読み込み関数"""
def load_json_data(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            logger.info (f'{file_path} read successfully.')
            return data
    except Exception as e:
        return {"error": str(e)}, 500

"""JSONファイルの書き込み関数"""
def write_json_data(file_path, new_data):
    try:
        # ディレクトリが存在しない場合は作成
        dir_path = os.path.dirname(file_path)
        if dir_path and not os.path.exists(dir_path):
            os.makedirs(dir_path)

        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(new_data, f, ensure_ascii=False, indent=4)
            return {"message": f"{file_path} updated successfully."}  # 標準の辞書を返す
    except Exception as e:
        return {"error": str(e)}, 500  # エラー情報を標準の形式で返す
    return None

"""画像ファイルをBase64エンコードして埋め込む"""
def img_to_base64(relative_path):
    # 📌 正しいパスを組み立てる（app/を意識する！）
    file_path = os.path.join(current_app.root_path, 'app', relative_path)
    try:
        with open(file_path, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
        return f"data:image/png;base64,{encoded_string}"
    except FileNotFoundError as e:
        logger.error(f"ファイルが見つかりません: {file_path}")
        raise e

"""Microsoft Graph APIの読み込み"""
def api_config():
    try:
        config = ApiConfig.query.first()
        if not config:
            raise ValueError("API設定が登録されていません。")

        client_id = config.client_id
        client_secret = config.client_secret
        tenant_id = config.tenant_id
        user_id = os.getenv('user_id') or ""
        redirect_uri = os.getenv('REDIRECT_URI') or ""
        authority = f"https://login.microsoftonline.com/{tenant_id}"

        # ★アプリ権限スコープ (.default)
        scopes = ["https://graph.microsoft.com/.default"]

        # ★ユーザー権限スコープ
        user_scopes = [
            "https://graph.microsoft.com/User.Read",
            "https://graph.microsoft.com/Mail.ReadWrite",
            "https://graph.microsoft.com/Notes.ReadWrite",
            "https://graph.microsoft.com/MailboxSettings.ReadWrite"
        ]

        if not all([client_id, client_secret, tenant_id, redirect_uri]):
            raise ValueError("API設定の取得に失敗しました（必須項目が未設定）。")

        return client_id, client_secret, tenant_id, user_id, redirect_uri, authority, scopes, user_scopes

    except Exception as e:
        raise RuntimeError(f"API設定の取得中にエラーが発生しました: {str(e)}")

"""Microsoft Graph API アクセストークン取得"""
def create_access_token():
    client_id, client_secret, tenant_id, _, _, authority, scopes, _ = api_config()
    authority = f'https://login.microsoftonline.com/{tenant_id}'
        
    msal_app = msal.ConfidentialClientApplication(client_id, authority=authority, client_credential=client_secret)
    
    # トークンを取得
    result = msal_app.acquire_token_for_client(scopes=scopes)
    
    if "access_token" in result:
        access_token = result['access_token']
        logger.info("Token acquired successfully")
        return access_token
    else:
        logger.error(f"Failed to get token: {result}")
        return None

# """セッションからユーザーのアクセストークンを取得し、必要に応じてリフレッシュ"""
# def get_user_access_token():
#     access_token = session.get("access_token")
#     refresh_token = session.get("refresh_token")

#     if not access_token:
#         raise Exception("ユーザーのアクセストークンがセッションに存在しません")

#     # アクセストークンの有効性を簡易チェック
#     response = requests.get(
#         "https://graph.microsoft.com/v1.0/me",
#         headers={"Authorization": f"Bearer {access_token}"}
#     )

#     if response.status_code == 200:
#         # 正常に使えるトークン
#         return access_token

#     elif response.status_code == 401 and refresh_token:
#         # アクセストークンが無効 → リフレッシュトークンを使って再取得
#         msal_app = current_app.config.get("MSAL_APP")
#         scopes = current_app.config.get("MS_SCOPES")

#         result = msal_app.acquire_token_by_refresh_token(refresh_token, scopes=scopes)

#         if "access_token" in result:
#             # 新しいアクセストークンとリフレッシュトークンを保存
#             session["access_token"] = result["access_token"]
#             session["refresh_token"] = result.get("refresh_token")
#             session.modified = True
#             return result["access_token"]
#         else:
#             raise Exception("リフレッシュトークンでアクセストークンの再取得に失敗しました")

#     else:
#         raise Exception(f"アクセストークンの確認中にエラーが発生しました: {response.status_code}, {response.text}")

"""通知からメッセージIDを抽出"""
def extract_message_id(notification):
    resource_data = notification.get('resourceData')
    resource = notification.get('resource', '')
    if resource_data and 'id' in resource_data:
        return resource_data['id']
    if 'messages/' in resource:
        return resource.split('/')[-1]
    return None

"""通知からuser_idを抽出"""
def extract_user_id(notification):
    resource_data = notification.get('resourceData')
    resource = notification.get('resource', '')
    if resource_data and '@odata.id' in resource_data:
        resource_path = resource_data['@odata.id']
        if resource_path.startswith('Users/'):
            return resource_path.split('/')[1]
    if resource.startswith('Users/'):
        return resource.split('/')[1]
    return None
    
"""gpt設定"""
def settings_gpt():
    try:
        with open("gpt_config.json", "r", encoding="utf-8") as f:
            config = json.load(f)

        model = config["model"]
        sys_content = config["sys_content"]
        user_content = config["user_content"]
        logger.info("gpt設定を取得しました")
        return model, sys_content, user_content

    except json.JSONDecodeError as e:
        logger.error(f"JSONDecodeError: {e}")
        logger.error(f"エラーの発生箇所: 行 {e.lineno}, 列 {e.colno}, 文字位置 {e.pos}")

    except FileNotFoundError:
        logger.error("gpt_config.json が見つかりません")
    except KeyError as e:
        logger.error(f"設定ファイルに必要なキーがありません: {e}")
    except Exception as e:
        logger.error(f"予期しないエラーが発生しました: {e}")

    # エラー時のデフォルト値（安全な fallback を返す）
    return "gpt-4-turbo", "システムプロンプト未取得", "ユーザープロンプト未取得"

"""section_nameごとにメールアドレスを抽出する関数"""
def extract_emails_by_section(data, notebooks_info):
    # マッピング用の辞書を準備
    section_email_map = {}

    # notebooks_info から分類名とブック名を紐付けるマップを作成
    section_to_notebook_map = {}
    section_links_map = {}

    for notebook in notebooks_info:
        notebook_name = notebook['displayName']
        for section in notebook.get('sections', []):
            section_name = section['displayName']
            section_to_notebook_map[section_name] = notebook_name
            section_links_map[section_name] = section['links']['oneNoteWebUrl']['href']

    # メールデータを処理
    for entry in data:
        if not isinstance(entry, dict):
            logging.warning("Unexpected type for entry: %s", type(entry))
            continue  # 辞書型でない場合はスキップ

        email = entry.get('from_email')
        category_names = entry.get('category_name', [])

        if email and category_names:
            for section_name in category_names:
                if section_name not in section_email_map:
                    section_email_map[section_name] = {
                        'ブック名': section_to_notebook_map.get(section_name, '未設定'),
                        '登録メールアドレス': [],
                        '分類件数': 0,
                        'リンク': section_links_map.get(section_name, 'N/A')  # タイトルを 'リンク' に変更
                    }
                # 登録メールアドレスの追加
                if email not in section_email_map[section_name]['登録メールアドレス']:
                    section_email_map[section_name]['登録メールアドレス'].append(email)
                # 分類件数のカウント
                section_email_map[section_name]['分類件数'] += 1

    # 重複削除と整形
    for section in section_email_map:
        section_email_map[section]['登録メールアドレス'] = list(set(section_email_map[section]['登録メールアドレス']))

    # 分類件数でソート（降順）
    section_email_map = dict(sorted(section_email_map.items(), key=lambda x: int(x[1]['分類件数']), reverse=True))

    return section_email_map

# """emailsテーブルのカテゴリ関連カラムを更新"""
# def update_email_categories_in_db(id, category_names, category_map):
#     try:
#         email_record = db.session.query(Email).filter_by(id=id).first()
#         if not email_record:
#             logger.warning(f"⚠️ DB内に対象メールが見つかりません: {id}")
#             return

#         # category_name は与えられた順を保持（Graph APIと整合）
#         email_record.categories = json.dumps(category_names)
#         email_record.category_name = json.dumps(category_names)

#         # category_id は map から引く（存在するもののみ）
#         category_ids = [
#             category_map.get(name, {}).get("category_id", "")
#             for name in category_names
#         ]
#         category_ids = [cid for cid in category_ids if cid]  # 空除去
#         email_record.category_id = json.dumps(category_ids)

#         # 更新日時
#         # email_record.updated_at = datetime.utcnow()

#         db.session.commit()
#         logger.info(f"✅ DBカテゴリ情報を更新: {id} / {category_names}")
#         return {"status": "success", "id": id, "category_names": category_names}

#     except Exception as e:
#         logger.error(f"❌ DBカテゴリ情報の更新中にエラー発生: {e}")
#         return {"status": "error", "id": id, "error": str(e)}