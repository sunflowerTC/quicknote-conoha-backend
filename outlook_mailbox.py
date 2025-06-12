import os
import re
import json
import time
from zoneinfo import ZoneInfo
import threading

from flask import current_app

import msal
import requests
from requests.exceptions import RequestException

from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone

import logging
from logging_config import setup_logging

from bs4 import BeautifulSoup
import base64

import openai
from openai import OpenAI

import openai_api

import utils
import google_api

from db.db import db
from models import Email

from sqlalchemy import func

# .envファイルを読み込む
load_dotenv('mailsystem.env')

tokyo_timezone = ZoneInfo("Asia/Tokyo")

"""ログファイル設定"""
logger = logging.getLogger("mailsystem")

"""カレントディレクトリを変更したいパスに設定"""
# 環境変数からプロジェクトルートパスを取得し、カレントディレクトリを変更
project_root = os.getenv('PROJECT_ROOT')

if project_root and os.path.isdir(project_root):
    os.chdir(project_root)
    logger.info(f"Current directory set to: {os.getcwd()}")
else:
    logger.error("PROJECT_ROOT is not set or the directory does not exist.")
    raise FileNotFoundError("The specified project root does not exist.")

"""現在の日時を取得"""
now_date, formatted_day_time = utils.current_date()

# user_id = os.getenv('user_mail')

"""サブスクリプションを作成"""
def create_subscription():
    user_id = os.getenv('user_mail')

    BASE_URL = os.getenv('BASE_URL').rstrip('/') + '/'
    access_token = utils.create_access_token()

    if not access_token:
        logger.error("❌ アクセストークンの取得に失敗しました")
        return

    # ⏳ 有効期限は現在から12時間後（最大）
    expiration_time = (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat()
    payload = {
        "changeType": "created,updated",
        "notificationUrl": f"{BASE_URL}webhook",
        "resource": f"users/{user_id}/mailFolders('inbox')/messages",
        "expirationDateTime": expiration_time,
        "clientState": os.getenv('GRAPH_CLIENT_STATE', 'secureSharedKey123')
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    res = requests.post("https://graph.microsoft.com/v1.0/subscriptions", headers=headers, data=json.dumps(payload))

    if res.status_code == 201:
        logger.info("✅ Graph サブスクリプション作成に成功")
        logger.info(f"🔁 subscriptionId: {res.get('id')}")
        logger.info(f"📅 有効期限: {res.get('expirationDateTime')}")
    else:
        logger.error(f"❌ サブスクリプション作成失敗: {res.status_code}")
        try:
            logger.error(f"詳細: {res.json()}")
        except Exception:
            logger.error(f"レスポンス: {res.text}")

"""サブスクリプションの有効性を確認し、必要に応じて更新"""
def ensure_subscription_valid():
    user_id = os.getenv('user_mail')

    RESOURCE = f"users/{user_id}/mailFolders('inbox')/messages"
    access_token = utils.create_access_token()
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    # ✅ 現在のサブスクリプション一覧を取得
    res = requests.get("https://graph.microsoft.com/v1.0/subscriptions", headers=headers)
    if res.status_code != 200:
        logger.error(f"❌ サブスクリプション一覧取得失敗: {res.status_code} - {res.text}")
        return

    subscriptions = res.json().get("value", [])
    now = datetime.now(timezone.utc)

    for sub in subscriptions:
        if sub.get("resource") == RESOURCE:
            expiration_str = sub.get("expirationDateTime")
            expiration = datetime.fromisoformat(expiration_str.replace("Z", "+00:00"))
            remaining = expiration - now

            if remaining > timedelta(hours=2):
                logger.info(f"✅ サブスクリプションは有効（残り: {remaining}）")
                return  # 有効期限が十分に残っている

            # ⏳ 期限が近い → 削除して再登録
            sub_id = sub.get("id")
            delete_res = requests.delete(f"https://graph.microsoft.com/v1.0/subscriptions/{sub_id}", headers=headers)
            if delete_res.status_code == 204:
                logger.info(f"🗑️ 古いサブスクリプションを削除しました (ID: {sub_id})")
            else:
                logger.warning(f"⚠️ サブスクリプション削除失敗: {delete_res.status_code} - {delete_res.text}")
            break  # 同一リソースの複数登録は避ける

    # ✅ 新規サブスクリプションを登録
    expiration_time = (now + timedelta(hours=12)).isoformat()
    payload = {
        "changeType": "created,updated",
        "notificationUrl": os.getenv("BASE_URL").rstrip('/') + "/webhook",
        "resource": RESOURCE,
        "expirationDateTime": expiration_time,
        "clientState": os.getenv("GRAPH_CLIENT_STATE", "secureSharedKey123")
    }

    reg_res = requests.post("https://graph.microsoft.com/v1.0/subscriptions", headers=headers, data=json.dumps(payload))
    if reg_res.status_code == 201:
        logger.info("📡 サブスクリプションを新規登録しました")
    else:
        logger.error(f"❌ サブスクリプション登録失敗: {reg_res.status_code} - {reg_res.text}")

"""メール履歴をDBから取得"""
def get_history(limit=200):
    try:
        # outlook_emails = db.session.query(Email).order_by(Email.received_date.desc()).all()
        # ✅ 最新順に最大500件のみ取得
        outlook_emails = (
            db.session.query(Email)
            .order_by(Email.received_date.desc())
            .limit(limit)
            .all()
        )
        # 各メールのデータが辞書形式かつ必要なフィールドのみが含まれるように処理
        cleaned_emails = []
        for email in outlook_emails:
            if email.received_date:
                received_date_utc = email.received_date.replace(tzinfo=timezone.utc)
                received_date_jst = received_date_utc.astimezone(tokyo_timezone)
                received_date_str = received_date_jst.strftime('%Y-%m-%d %H:%M:%S')
            else:
                received_date_str = "不明"

            try:
                category_id = json.loads(email.category_id) if email.category_id else []
            except Exception as e:
                logger.warning(f"⚠️ category_idの変換に失敗: {e}")
                category_id = []

            try:
                category_name = json.loads(email.category_name) if email.category_name else []
            except Exception as e:
                logger.warning(f"⚠️ category_nameの変換に失敗: {e}")
                category_name = []

            cleaned_email = {
                "subject": email.subject,
                "sender_name": email.sender_name,
                "sender_email": email.sender_email,
                "received_date": received_date_str,
                "category_name": category_name,
                "priority_ai": email.priority_ai,
                "summary": email.summary,
                "web_link": email.web_link
            }
            cleaned_emails.append(cleaned_email)
        logger.info("メール履歴を取得しました: %d 件", len(cleaned_emails))
        return cleaned_emails

    except json.JSONDecodeError as e:
        logger.error("JSONファイルの形式が正しくありません: %s", e)
        return None

"""メールの詳細情報を取得"""
def get_email_details(access_token, message_id):
    user_id = os.getenv('user_mail')

    graph_api_endpoint = f"https://graph.microsoft.com/v1.0/users/{user_id}/messages/{message_id}"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    response = requests.get(graph_api_endpoint, headers=headers)
    if response.status_code == 200:
        logger.info("📡 メール詳細情報を取得しました")
        return response.json()  # メール詳細情報を返す
    else:
        logger.error(f"メール詳細情報の取得失敗: {response.status_code}")
        return None

"""ユーザーのカテゴリ一覧を取得"""
def get_user_master_categories(user_access_token, graph_user_id):
    headers = {
        'Authorization': f'Bearer {user_access_token}',
        'Content-Type': 'application/json'
    }
    url = f'https://graph.microsoft.com/v1.0/users/{graph_user_id}/outlook/masterCategories'
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        categories_data = response.json()
        return [category['displayName'] for category in categories_data.get('value', [])]
    else:
        logger.error(f"Failed to retrieve master categories: {response.status_code}, {response.text}")
        return []

"""有効なカテゴリのみを抽出する"""
def filter_valid_categories(categories, master_categories):
    return [category for category in categories if category in master_categories]

"""カテゴリー判定"""
def settings_judgement(from_email):
    try:
        # JSONファイルから設定を読み込む
        with open("category_config.json", "r", encoding="utf-8") as f:
            category_config = json.load(f)
        
        # from_email に一致するエントリが存在するか確認
        sections = category_config.get(from_email, [])
        
        # 各セクションの section_id と section_name を取得
        section_info = [
            (
                section.get("notebook", {}).get("notebook_id", ""),
                section.get("notebook", {}).get("notebook_name", "未設定"),
                section.get("section", {}).get("section_id", ""),
                section.get("section", {}).get("section_name", "未設定")
            )
            for section in sections
        ]
        
        # section_info が空の場合は「未設定」を追加
        if not section_info:
            section_info.append(("","未設定", "", "未設定"))

        logger.info(
            f"from_email: {from_email} / section_info: " +
            ", ".join([
                f"[Notebook: {notebook} (ID: {notebook_id}), Section: {section_name} (ID: {section_id})]"
                for notebook_id, notebook, section_id, section_name in section_info
            ])
        )

        logger.info("カテゴリー設定を取得しました")
        
        return section_info
    
    except FileNotFoundError:
        return [("カテゴリ設定ファイルが見つかりません", None, None)]
    except json.JSONDecodeError:
        return [("カテゴリ設定ファイルの形式が正しくありません", None, None)]

"""メール内容に応じてuser_contentを生成"""
def generate_user_content(subject, body, category_names, user_content_template):
    category_str = ", ".join(category_names)

    if len(category_names) == 1:
        categories_text = f"{category_str}（この1つから必ず選んでください）"
    else:
        categories_text = f"{category_str}"

    # テンプレート内の {categories_text} を差し込む形式に変更
    try:
        return user_content_template.format(
            subject=subject,
            body=body,
            categories=categories_text,
        )
    except KeyError as e:
        logger.error(f"❌ プロンプトテンプレートのプレースホルダが不足しています: {e}")
        return ""

"""要約、優先度、カテゴリを抽出する"""
def extract_summary_priority_category(text):
    if not isinstance(text, str):
        logger.warning("⚠️ ChatGPTの応答がNoneまたは文字列ではありません")
        return "", "", ""

    summary_pattern = r"要約:\s*(.*?)(?:\n|$)"
    priority_pattern = r"優先度[:：]?\s*['\"]?(\w+)"
    category_pattern = r"推奨カテゴリ[:：]?\s*['\"]?([^\n]+)"

    summary_match = re.search(summary_pattern, text, re.DOTALL)
    priority_match = re.search(priority_pattern, text)
    category_match = re.search(category_pattern, text)

    summary = summary_match.group(1).strip() if summary_match else "要約が見つかりません"
    priority_ai = priority_match.group(1).strip() if priority_match else "優先度が見つかりません"
    selected_category = category_match.group(1).strip() if category_match else "未設定"

    logger.info("✅ 要約、優先度、推奨カテゴリを抽出しました")
    return summary, priority_ai, selected_category

"""メールの要約と優先度を推測"""
def classify_and_summarize_email(subject, body, category_names):
    organization, api_key = openai_api.get_openai_key()
    openai.organization = organization if organization else None
    openai.api_key = api_key

    model, sys_content, user_content_template = utils.settings_gpt()
    user_content = generate_user_content(subject, body, category_names, user_content_template)

    try:
        response = openai.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": sys_content},
                {"role": "user", "content": user_content}
            ]
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logger.error(f"Error occurred during classification: {e}")
        return None

"""Base64エンコードされた添付ファイルを保存する"""
def save_attachment(file_name, file_data, save_dir):
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)  # 保存先ディレクトリを作成

    file_path = os.path.join(save_dir, file_name)

    try:
        # Base64データをデコードしてバイナリで保存
        with open(file_path, "wb") as f:
            f.write(base64.b64decode(file_data))
        print(f"添付ファイルを保存しました: {file_path}")
    except Exception as e:
        print(f"添付ファイルの保存中にエラーが発生しました: {e}")

"""添付ファイル情報を取得（ショートカット作成対応版）"""
def get_attachments(message_id, access_token, user_id, notebook_names, category_names):
    attachments_endpoint = f'https://graph.microsoft.com/v1.0/users/{user_id}/messages/{message_id}/attachments'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    response = requests.get(attachments_endpoint, headers=headers)

    if response.status_code != 200:
        logger.error(f"❌ 添付ファイル取得失敗: {response.status_code}")
        logger.error(f"❌ レスポンス内容（先頭500文字）: {response.text[:500]}")
        return []

    try:
        json_data = response.json()
        attachments_data = json_data.get('value', [])
    except requests.exceptions.JSONDecodeError as e:
        logger.error(f"❌ JSONデコードエラー: {e}")
        logger.error(f"❌ レスポンスContent-Type: {response.headers.get('Content-Type')}")
        logger.error(f"❌ レスポンス本文（先頭500文字）: {response.text[:500]}")
        return []
        
    file_names = [a.get('name', 'unknown') for a in attachments_data]
    logger.info(f"📎 添付ファイル一覧: {file_names}")

    if response.status_code != 200:
        logger.error(f"Error retrieving attachments: {response.status_code}")
        return []

    attachments = []
    today_folder = datetime.now().strftime("%Y-%m-%d")
    app = current_app._get_current_object()

    already_uploaded_files = set()
    for attachment in response.json().get('value', []):
        file_name = attachment.get('name', 'unknown')
        file_data = attachment.get('contentBytes', '')

        if not file_data or not file_data.strip():
            logger.warning(f"⚠️ 添付ファイル {file_name} が空データのためスキップ")
            continue

        # ✅ ここで重複チェック
        if file_name in already_uploaded_files:
            logger.info(f"🚫 重複ファイル名検知によりスキップ: {file_name}")
            continue
        already_uploaded_files.add(file_name)

        # ✅ 1回だけ、日付フォルダにファイル本体をアップロード
        try:
            uploaded_file_id = google_api.upload_to_drive_and_get_id_by_day(
                file_name, file_data, today_folder, app
            )
            if uploaded_file_id:
                uploaded_file_url = f"https://drive.google.com/file/d/{uploaded_file_id}/view"
                logger.info(f"✅ ファイル {file_name} アップロード完了: {uploaded_file_url}")
            else:
                logger.error(f"❌ ファイル {file_name} のアップロードに失敗")
                continue
        except Exception as e:
            logger.error(f"❌ ファイル {file_name} のアップロードエラー: {e}")
            continue

        uploaded_to_category = set()

        # ✅ notebook_name × category_name ごとにショートカットを作成
        for notebook_name, category_name in zip(notebook_names, category_names):
            if category_name == "未設定":
                logger.info(f"✅ カテゴリ未設定のためスキップ: {file_name}")
                continue

            key = (notebook_name, category_name, file_name)
            if key in uploaded_to_category:
                logger.info(f"✅ すでにショートカット作成済みスキップ: {key}")
                continue

            try:
                # 🛠 notebookフォルダを取得
                shared_root_folder_id = google_api.get_shared_folder_id_by_name(notebook_name)

                # 🛠 その中の category フォルダを取得 or 作成
                category_folder_id = google_api.create_folder_if_not_exists(
                    folder_name=category_name,
                    parent_folder_id=shared_root_folder_id
                )

                if not category_folder_id:
                    logger.error(f"❌ カテゴリフォルダ取得失敗: {notebook_name}/{category_name}")
                    continue

                # 🛠 ショートカット作成
                shortcut_id = google_api.create_shortcut_to_drive(
                    file_id=uploaded_file_id,
                    shortcut_name=file_name,
                    parent_folder_id=category_folder_id,
                    app=app
                )

                if shortcut_id:
                    shortcut_url = f"https://drive.google.com/file/d/{shortcut_id}/view"

                    attachments.append({
                        "name": file_name,
                        "content_type": attachment.get('contentType'),
                        "size": attachment.get('size'),
                        "notebook_name": notebook_name,
                        "category_name": category_name,
                        "url": shortcut_url
                    })

                    logger.info(f"✅ ショートカット作成成功: {file_name} → {notebook_name}/{category_name} / URL: {shortcut_url}")
                    uploaded_to_category.add(key)
                else:
                    logger.error(f"❌ ショートカット作成失敗: {file_name} → {notebook_name}/{category_name}")

            except Exception as e:
                logger.error(f"❌ ショートカット作成エラー: {file_name} in {category_name} / {e}")

    return attachments

"""各メールの全フィールドを抽出"""
def extract_full_email_data(email, access_token, change_type="created", last_categories_remote=None, last_modified_remote=None):
    # ✅ 初期化（どの分岐でも使えるように）
    summary = ""
    priority_ai = ""
    attachments = []
    notebook_names = []
    notebook_id = []
    category_names = []
    category_id = []

    user_id = os.getenv('user_mail')

    subject = email.get('subject')
    if not subject or not isinstance(subject, str):
        logger.warning(f"⚠️ subject が未設定または不正（email_id: {email.get('id')}）")
        subject = ""

    body_content = email.get('body', {}).get('content', '')
    
    # HTML形式の本文をテキストに変換
    if email.get('body', {}).get('contentType') == 'html':
        soup = BeautifulSoup(body_content, 'html.parser')
        body_text = soup.get_text(separator='\n').strip()
    else:
        body_text = body_content

    # メールのカテゴリ
    change_key = email.get('changeKey', '')
    logger.info(f"✅ changeKeyを取得: {change_key}")

    from_email = email.get('from', {}).get('emailAddress', {}).get('address', 'Unknown')
    section_info = settings_judgement(from_email)
    # カテゴリ名 → ID、ノートブック名、ノートブックID の辞書を構築
    category_map = {
        section[3]: {
            "category_id": section[2],
            "notebook_id": section[0],
            "notebook_name": section[1]
        }
        for section in section_info
    }
    category_names = list(category_map.keys())  # 推奨カテゴリ候補用に保持

    if category_map:
        notebook_names = list({v["notebook_name"] for v in category_map.values()})

    logger.info(f'notebook_names: {notebook_names} / category_names: {category_names}')

    # 「その他」のカテゴリの場合、要約・優先度をスキップ
    if category_names == ["未設定"]:
        summary = ""
        priority_ai = ""
        attachments = []
        category_id = [""]
        notebook_id = [""]
        notebook_names = ["未設定"]
        category_names = ["未設定"]

    elif change_type == "updated":
        logger.info("🛠️ change_type == 'updated' 用の分岐処理")
        category_names = last_categories_remote or ["未設定"]
        if category_names == ["未設定"]:
            category_id = [""]
            notebook_id = [""]
            notebook_names = ["未設定"]
        else:
            selected_category = category_names[0]
            if selected_category in category_map:
                category_id = [category_map[selected_category]["category_id"]]
                notebook_id = [category_map[selected_category]["notebook_id"]]
                notebook_names = [category_map[selected_category]["notebook_name"]]
            else:
                category_id = [""]
                notebook_id = [""]
                notebook_names = ["未設定"]
                category_names = ["未設定"]

            existing = db.session.query(Email).filter_by(graph_id=email.get("id")).first()
            if existing:
                # メールの要約と優先度
                existing_categories = json.loads(existing.categories) if existing.categories else []

                # 変更されている場合のみ AI による判定を実行
                # if existing.last_modified != last_modified_remote and set(existing_categories) != set(last_categories_remote or []):
                if existing.last_modified != last_modified_remote and not set(last_categories_remote or []).issubset(set(existing_categories)):
                    result = classify_and_summarize_email(subject, body_text, category_names)
                    summary, priority_ai, _ = extract_summary_priority_category(result)
                    logger.info(f"🎯 AIが要約・優先度を判定しました: {from_email}")

                    # 添付ファイルの取得
                    if email.get('hasAttachments', False):
                        attachments = get_attachments(
                            email['id'], access_token, user_id, notebook_names, category_names
                        )
                else:
                    logger.info("📌 カテゴリに変更がないため AI 処理はスキップします")

        # if email.get('hasAttachments', False):
        #     attachments = get_attachments(
        #         email['id'], access_token, user_id, notebook_names, category_names
        #     )

    else:
        # メールの要約と優先度
        result = classify_and_summarize_email(subject, body_text, category_names)
        logger.info(f"🎯 AIが要約・優先度・カテゴリを判定しました: {from_email}")
        summary, priority_ai, selected_category = extract_summary_priority_category(result)

        selected_category = selected_category.strip()
        # category_names の中から選ばれたカテゴリを反映
        if selected_category in category_map:
            logger.info(f"🎯 AIがカテゴリを選定しました: {selected_category}")
            category_id = [category_map[selected_category]["category_id"]]
            notebook_id = [category_map[selected_category]["notebook_id"]]
            notebook_names = [category_map[selected_category]["notebook_name"]]
            category_names = [selected_category]

            logger.info(f"📋 カテゴリ一覧: {category_names}")
            logger.info(f"🔍 推奨カテゴリ: {selected_category}")
            logger.info(f"🆔 カテゴリID一覧: {category_id}")
        else:
            logger.warning(f"⚠️ 推奨カテゴリ '{selected_category}' が候補に含まれません。未設定とします。")
            category_id = [""]
            notebook_id = [""]
            notebook_names = ["未設定"]
            category_names = ["未設定"]

        # ✅ 念のため fallback（保険）
        if not category_id:
            logger.warning("⚠️ category_id が未定義のため、強制的に未設定にします。")
            category_id = [""]

        # 添付ファイルの取得（各カテゴリ名に基づいて処理）
        attachments = []
        if change_type == "created" and email.get('hasAttachments', False):
            attachments = get_attachments(
                email['id'],
                access_token,
                user_id,
                notebook_names,
                category_names
            )
    
    # 保存用IDを決定（internet_message_id優先）
    internet_message_id = email.get('internetMessageId')
    graph_message_id = email.get('id')
    save_id = internet_message_id or graph_message_id

    if not save_id:
        logger.warning("⚠️ 保存用IDが決定できないメールのためスキップします")
        return None  # 保存不可データ

    return {
        "id": save_id,
        "graph_id": graph_message_id,
        "change_key": change_key,
        "subject": subject,
        "from_name": email.get('from', {}).get('emailAddress', {}).get('name', 'Unknown'),
        "from_email": from_email,
        "sender_name": email.get('sender', {}).get('emailAddress', {}).get('name', 'Unknown'),
        "sender_email": email.get('sender', {}).get('emailAddress', {}).get('address', 'Unknown'),
        "to_recipients": [
            recipient.get('emailAddress', {}).get('address', 'Unknown')
            for recipient in email.get('toRecipients', [])
        ],
        "cc_recipients": [
            recipient.get('emailAddress', {}).get('address', 'Unknown')
            for recipient in email.get('ccRecipients', [])
        ],
        "bcc_recipients": [
            recipient.get('emailAddress', {}).get('address', 'Unknown')
            for recipient in email.get('bccRecipients', [])
        ],
        "received_date": email.get('receivedDateTime', 'Unknown'),
        "notebook_id": notebook_id,  # DB未登録
        "notebook_name": notebook_names,  # DB未登録
        "category_id": category_id,
        "category_name": category_names,
        "priority_ai": priority_ai,
        "sent_date": email.get('sentDateTime', 'Unknown'),
        "has_attachments": email.get('hasAttachments', False),
        "attachments": attachments,
        "internet_message_id": email.get('internetMessageId', 'Unknown'),
        "conversation_id": email.get('conversationId', 'Unknown'),
        "is_read": email.get('isRead', False),
        "summary": summary,
        "body_preview": email.get('bodyPreview', 'No Body Preview'),
        "body_text": body_text,  # 変換後の本文テキスト
        "importance": email.get('importance', 'normal'),
        "inference_classification": email.get('inferenceClassification', 'other'),
        "web_link": email.get('webLink', 'Unknown'),
        "categories": category_names,
        "last_modified": email.get("lastModifiedDateTime"),
        "change_type": change_type
    }

"""メールのカテゴリを更新する"""
def patch_email_category(access_token, email_id, user_id, categories, change_key):
    endpoint = f'https://graph.microsoft.com/v1.0/users/{user_id}/messages/{email_id}'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
        'If-Match': change_key
    }
    payload = {'categories': categories}
    return requests.patch(endpoint, headers=headers, json=payload)

"""メールのカテゴリをGraph APIで更新する関数"""
def update_email_categories(user_access_token, processed_emails, graph_user_id, change_key):
    results = []  # 更新結果を保存するリスト

    # processed_emails が dict の場合はリストに変換する
    if isinstance(processed_emails, dict):
        processed_emails = [processed_emails]

    # ユーザーのマスターカテゴリ一覧を取得
    master_categories = get_user_master_categories(user_access_token, graph_user_id)

    for email in processed_emails:
        id = email.get('internet_message_id')
        email_id = email.get('graph_id')
        categories = email.get('categories', [])

        # 有効なカテゴリのみを抽出
        valid_categories = filter_valid_categories(categories, master_categories)

        # ✅ 未登録カテゴリの検出
        invalid_categories = [c for c in categories if c not in master_categories]
        if invalid_categories:
            logger.warning(f"⚠️ メール（ID: {email_id}）に未登録カテゴリが含まれています: {invalid_categories}")

        if not valid_categories:
            logger.info(f"⏩ Email {email_id} に設定可能なカテゴリがありません。スキップします。")
            results.append({'email_id': email_id, 'status': 'skipped', 'reason': 'No valid categories'})
            continue

        response = patch_email_category(user_access_token, email_id, graph_user_id, valid_categories, change_key)

        if response is None:
            results.append({'email_id': email_id, 'status': 'failure', 'error': 'patch connection failed'})
            continue

        if response.status_code == 200:
            logger.info(f"📧 メール（ID: {email_id}）カテゴリ更新成功。カテゴリ: {categories}")
            results.append({'email_id': email_id, 'status': 'success'})
            continue

        elif response.status_code == 412:
            logger.warning(f"⚠️ メール（ID: {email_id}）カテゴリ更新失敗（412）。changeKey 再取得してリトライ。")
            try:
                email_detail = get_email_details(user_access_token, email_id)
                new_key = email_detail.get("changeKey") if email_detail else None
            except Exception as e:
                logger.error(f"❌ changeKey再取得エラー: {e}")
                results.append({'email_id': email_id, 'status': 'failure', 'error': 'changeKey fetch exception'})
                continue

            if new_key:
                retry = patch_email_category(user_access_token, email_id, graph_user_id, categories, new_key)

                if retry and retry.status_code == 200:
                    logger.info(f"✅ リトライ成功: メール（ID: {email_id}）カテゴリ更新。カテゴリ: {categories}")                        
                    results.append({'email_id': email_id, 'status': 'success', 'retry': True})
                else:
                    err_text = retry.text if retry else "connection failed"
                    logger.error(f"❌ リトライ失敗: {err_text}")
                    results.append({'email_id': email_id, 'status': 'failure', 'error': err_text, 'retry': True})
            else:
                logger.error(f"❌ changeKey の再取得に失敗")
                results.append({'email_id': email_id, 'status': 'failure', 'error': 'changeKey is None'})
        else:
            logger.error(f"❌ メール（ID: {email_id}）カテゴリ更新失敗: {response.status_code}, {response.text}")
            results.append({'email_id': email_id, 'status': 'failure', 'error': response.text})

    return results
    
"""最終メール受信日時をJsonから取得"""
def get_last_date():
    try:
        # DBから最大の受信日時を取得
        max_date_obj = db.session.query(func.max(Email.received_date)).scalar()

        if not max_date_obj:
            return None, "不明"

        received_date_utc = max_date_obj.replace(tzinfo=timezone.utc)
        received_date_jst = received_date_utc.astimezone(tokyo_timezone)
        received_date_str = received_date_jst.strftime('%Y-%m-%d %H:%M:%S')

        logging.info("最終メール受信日時をDBから取得しました: %s", received_date_str)
        return received_date_str

    except Exception as e:
        logging.error("DBからの受信日時取得に失敗しました: %s", e)
        return None, "不明"

"""メールの詳細情報を取得し、DBに保存する関数"""
def mail_processing(access_token, message_id, change_type="created"):
    logger.info("QuickNote for Outlook - start")

    # メールの詳細情報を取得
    message_details = get_email_details(access_token, message_id)
    if not message_details:
        logger.error("メールの詳細情報が取得できませんでした")
        return None, "message_details is None"

    # logger.info(f"message_details: {message_details}")

    # Graph API からの最終更新時刻
    last_modified_remote = message_details.get("lastModifiedDateTime")
    last_categories_remote = message_details.get("categories", [])

    if not last_modified_remote:
        logger.info(f"lastModifiedDateTime が存在しません: {message_id}")
        return None, "last_modified_missing"
    else:
        time.sleep(5)  # APIのレート制限対策として少し待機
        existing = db.session.query(Email).filter_by(graph_id=message_id).first()
        existing_categories = json.loads(existing.categories) if existing and existing.categories else []

        logger.info(f"最終更新時刻: {last_modified_remote} / カテゴリ: {last_categories_remote}")

        if existing and (
            existing.last_modified == last_modified_remote or
            set(existing_categories) == set(last_categories_remote)
        ):
            logger.info(f"🔁 変更なしのため処理スキップ: {message_id}")
            return None, "no_change"

    # メールのカテゴリを判定
    full_email = extract_full_email_data(message_details, access_token, change_type=change_type, last_categories_remote=last_categories_remote, last_modified_remote=last_modified_remote)
    logger.info(f"カテゴリを実行しました: {change_type} / カテゴリ: {last_categories_remote}")

    if not full_email:
        logger.error("📛 full_email の抽出に失敗しました")
        return None, "full_email is None"

    logger.info("QuickNote for Outlook - fin")

    return full_email, None