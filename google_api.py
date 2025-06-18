import os
import re
import unicodedata
import base64
import threading

from flask import current_app
from db.db import db
from models import Account, Job, ApiConfig

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaInMemoryUpload

import logging

from queue import Queue

import utils

result_queue = Queue()

"""ログファイル設定"""
logger = logging.getLogger("mailsystem")

"""許可するファイル拡張子"""
ALLOWED_EXTENSIONS = {'.pdf', '.docx', '.xls', '.xlsx', '.jpg', '.png', '.txt', '.zip', '.csv', '.pptx', '.mp4'}

"""最大ファイルサイズ (バイト単位、例: 10MB)"""
MAX_FILE_SIZE = 20 * 1024 * 1024

"""google service accountの読み込み"""
def google_config():
    try:
        config = ApiConfig.query.first()
        if config and config.service_account_file:
            return config.service_account_file
        else:
            logger.error("サービスアカウントファイルが設定されていません")
            raise ValueError("サービスアカウントファイルが設定されていません")
    except Exception as e:
        logger.error("サービスアカウントの取得に失敗しました")
        raise RuntimeError(f"サービスアカウントの取得に失敗しました: {e}")

"""SSの認証設定"""
def set_auth_ss():
    SCOPES = ['https://www.googleapis.com/auth/drive']
    SERVICE_ACCOUNT_FILE = google_config()  # ← DBから取得に変更

    credentials = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES
    )
    drive_service = build('drive', 'v3', credentials=credentials)
    
    return drive_service

def list_shared_folders():
    drive_service = set_auth_ss()
    response = drive_service.files().list(
        q="sharedWithMe and mimeType='application/vnd.google-apps.folder' and trashed = false",
        spaces='drive',
        fields='files(id, name)',
        supportsAllDrives=True
    ).execute()
    return response.get('files', [])

def get_shared_folder_id_by_name(folder_name):
    shared_folders = list_shared_folders()
    matched_folders = [f for f in shared_folders if f['name'] == folder_name]

    if not matched_folders:
        raise ValueError(f"共有フォルダ '{folder_name}' が見つかりませんでした。")

    if len(matched_folders) > 1:
        logger.warning(f"⚠️ 共有フォルダ '{folder_name}' が複数見つかりました。最初の1つを使用します。全件: {[f['id'] for f in matched_folders]}")

    return matched_folders[0]['id']

"""親フォルダIDをフォルダ名から取得または作成"""
def create_folder_if_not_exists(folder_name, parent_folder_id):
    drive_service = set_auth_ss()

    query = f"'{parent_folder_id}' in parents and name = '{folder_name}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
    results = drive_service.files().list(
        q=query,
        fields="files(id, name)",
        supportsAllDrives=True
    ).execute()

    files = results.get('files', [])

    if len(files) == 1:
        folder_id = files[0]['id']
        logger.info(f"✅ 既存フォルダ '{folder_name}' のIDを取得: {folder_id}")
        return folder_id

    elif len(files) > 1:
        # 一意でない → 全件ログ出力 + 警告
        logger.warning(f"⚠️ フォルダ '{folder_name}' が複数存在します。最初の1つを使用します。全件: {[f['id'] for f in files]}")
        return files[0]['id']

    # 見つからなかった → 作成する
    logger.info(f"🆕 フォルダ '{folder_name}' が見つからないため新規作成します")
    file_metadata = {
        'name': folder_name,
        'mimeType': 'application/vnd.google-apps.folder',
        'parents': [parent_folder_id]
    }
    folder = drive_service.files().create(
        body=file_metadata,
        fields='id',
        supportsAllDrives=True
    ).execute()
    folder_id = folder.get('id')
    logger.info(f"✅ フォルダ '{folder_name}' を作成しました。ID: {folder_id}")
    return folder_id

"""ファイル名のサニタイズ"""
def sanitize_filename(file_name):
    safe_name = os.path.basename(file_name)
    # 全角スペースや不可視文字を除去・変換
    safe_name = safe_name.replace('\u3000', ' ')  # 全角スペース → 半角
    safe_name = ''.join(c for c in safe_name if unicodedata.category(c)[0] != "C")  # 制御文字除去

    # 連続ドットを1つに変換
    safe_name = re.sub(r'\.{2,}', '.', safe_name)

    # パス区切り文字の除去（OSに依存）
    safe_name = safe_name.replace('/', '').replace('\\', '')

    # Windows 禁止文字の除去（必要なら他のOSにも対応可能）
    safe_name = re.sub(r'[<>:"/\\|?*]', '_', safe_name)

    # ピリオドだけのファイル名や拡張子無しを避ける
    safe_name = safe_name.strip('. ').strip()
    return safe_name

"""ファイルタイプが許可されているかチェック"""
def is_allowed_file(file_name):
    _, extension = os.path.splitext(file_name)
    return extension.lower() in ALLOWED_EXTENSIONS

"""ファイルサイズが許容範囲内かチェック"""
def is_file_size_allowed(file_data):
    try:
        return len(base64.b64decode(file_data)) <= MAX_FILE_SIZE
    except Exception as e:
        logger.error(f"ファイルサイズの確認中にエラー: {e}")
        return False

"""MIMEタイプ取得"""
def get_mime_type(file_path):
    import mimetypes
    mime_type, _ = mimetypes.guess_type(file_path)
    return mime_type or 'application/octet-stream'

"""フォルダ内で重複しないファイル名を作成する関数"""
def get_unique_filename(file_name, folder_id):
    drive_service = set_auth_ss()
    try:
        base_name, extension = os.path.splitext(file_name)
        query = f"'{folder_id}' in parents and trashed = false"
        results = drive_service.files().list(q=query, fields="files(name)", supportsAllDrives=True).execute()
        existing_files = [file['name'] for file in results.get('files', [])]

        count = 1
        new_name = file_name
        while new_name in existing_files:
            new_name = f"{base_name}({count}){extension}"
            count += 1
        return new_name
    except Exception as e:
        logger.error(f"ファイル名生成中にエラー: {e}")
        return file_name

"""Google Driveへショートカットを作成する"""
def create_shortcut_to_drive(file_id, shortcut_name, parent_folder_id, app):
    # すでにある共通認証関数を利用する
    service = set_auth_ss()

    shortcut_metadata = {
        'name': shortcut_name,
        'mimeType': 'application/vnd.google-apps.shortcut',
        'parents': [parent_folder_id],
        'shortcutDetails': {
            'targetId': file_id
        }
    }

    try:
        file = service.files().create(body=shortcut_metadata, fields='id').execute()
        logger.info(f"✅ ショートカット '{shortcut_name}' をカテゴリフォルダに作成しました")
        return file.get('id')
    except Exception as e:
        logger.error(f"❌ ショートカット作成エラー: {e}")
        return None

"""Google Driveへファイルをアップロード"""
def upload_to_drive(file_name, file_data, folder_id, app):
    with app.app_context():
        drive_service = set_auth_ss()

        try:
            decoded_file_data = base64.b64decode(file_data)
            mime_type = get_mime_type(file_name)
            unique_file_name = get_unique_filename(sanitize_filename(file_name), folder_id)

            file_metadata = {
                'name': unique_file_name,
                'parents': [folder_id]
            }
            media = MediaInMemoryUpload(decoded_file_data, mimetype=mime_type, resumable=True)

            file = drive_service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id, webViewLink',
                supportsAllDrives=True
            ).execute()

            logger.info(f"ファイル '{unique_file_name}' をアップロードしました。ファイルID: {file.get('id')}")
            logger.info(f"🔗 閲覧リンク: {file.get('webViewLink')}")
            return {
                "file_id": file.get("id"),
                "view_link": file.get("webViewLink")
            }
        except Exception as e:
            logger.error(f"ファイルアップロード中にエラー: {e}")
            return None

"""日付フォルダに基づいてファイルをアップロードし、ファイルIDを返す"""
def upload_to_drive_and_get_id_by_day(file_name, file_data, day_folder_name, app):
    with app.app_context():
        try:
            safe_file_name = sanitize_filename(file_name)

            if not is_allowed_file(safe_file_name):
                _, ext = os.path.splitext(safe_file_name)
                logger.error(f"❌ 許可されていない拡張子: {ext} / 元ファイル名: {file_name}")
                return None

            if not is_file_size_allowed(file_data):
                logger.error("ファイルサイズが大きすぎます")
                return None

            # ① 共有ルートフォルダを取得
            try:
                shared_root_folder_id = get_shared_folder_id_by_name("QuickNote_Attachment")
                logger.info(f"📁 共有ルートフォルダID: {shared_root_folder_id}")
            except Exception as e:
                logger.error(f"❌ QuickNote_Attachment フォルダの取得に失敗: {e}")
                return None

            # ② 日付フォルダを取得または作成
            try:
                day_folder_id = create_folder_if_not_exists(day_folder_name, parent_folder_id=shared_root_folder_id)
                logger.info(f"📂 日付フォルダ '{day_folder_name}' ID: {day_folder_id}")
            except Exception as e:
                logger.error(f"❌ 日付フォルダの作成に失敗: {e}")
                return None

            # ③ ファイルをアップロード
            result = upload_to_drive(safe_file_name, file_data, day_folder_id, app)
            # file_id = upload_to_drive(safe_file_name, file_data, day_folder_id, app)

            if result:
                file_id = result["file_id"]
                view_link = result["view_link"]
                logger.info(f"✅ ファイル '{safe_file_name}' をアップロード。リンク: {view_link}")
                return file_id, view_link  # 👈 OneNote 用にリンクを返す

            # if file_id:
            #     logger.info(f"✅ ファイル '{safe_file_name}' を QuickNote_Attachment/{day_folder_name} にアップロードしました")
            #     return file_id
            else:
                logger.error(f"❌ ファイル '{safe_file_name}' のアップロードに失敗しました")
                return None

        except Exception as e:
            logger.error(f"❌ {file_name} の日付フォルダ保存中にエラー: {e}")
            return None
