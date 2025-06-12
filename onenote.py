import os
import requests
import json
import copy

import logging
from logging_config import setup_logging

from dotenv import load_dotenv

import utils

import html


load_dotenv("mailsystem.env")

"""ログファイル設定"""
logger = logging.getLogger("mailsystem")

"""OneNote情報のタイムゾーンを変換"""
def convert_all_dates_to_japan_time(data):
    for notebook in data:
        notebook["createdDateTime"] = utils.convert_to_japan_time(notebook["createdDateTime"])
        notebook["lastModifiedDateTime"] = utils.convert_to_japan_time(notebook["lastModifiedDateTime"])
        for section in notebook.get("sections", []):
            section["createdDateTime"] = utils.convert_to_japan_time(section["createdDateTime"])
            section["lastModifiedDateTime"] = utils.convert_to_japan_time(section["lastModifiedDateTime"])
    return data

"""特定のノートブックのセクション一覧を取得する関数"""
def get_sections(notebook_id, access_token):
    url = f"https://graph.microsoft.com/v1.0/users/me/onenote/notebooks/{notebook_id}/sections"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # HTTPエラーが発生した場合は例外をスロー

        try:
            sections = response.json().get("value", [])
            if not sections:
                logging.info(f"ノートブック '{notebook_id}'（URL: {url}）にはセクションが見つかりません。")
            else:
                logging.info(f"取得したセクション一覧: {[section['displayName'] for section in sections]}")
            return sections
        except ValueError:
            logging.error(f"レスポンスをJSONとして解析できませんでした: {response.text}")
            return []

    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTPエラーが発生しました: {http_err} - ステータスコード: {response.status_code}")
        if response.status_code == 403:
            logging.error("アクセス権限が不足している可能性があります。")
    except requests.exceptions.RequestException as err:
        logging.error(f"リクエスト中にエラーが発生しました: {err}")

    return []

"""ノートブックの一覧を取得する関数"""
def get_notebooks(user_id, access_token_onenote):
    if not access_token_onenote:
        logger.error("トークンが存在しません。")
        return None, None

    url = f"https://graph.microsoft.com/v1.0/users/{user_id}/onenote/notebooks?$expand=sections"
    headers = {
        "Authorization": f"Bearer {access_token_onenote}"
    }

    response = requests.get(url, headers=headers)
    logger.info(f'notebooks_api: {response.status_code}')

    if response.status_code == 200:
        try:
            notebooks = response.json().get("value", [])
            if not isinstance(notebooks, list):
                raise ValueError("notebooksの形式がリストではありません")

            json_data = json.dumps(notebooks, ensure_ascii=False, indent=4)
            file_path = "notebooks_info.json"
            utils.write_json_data(file_path, notebooks)

            return notebooks, json_data
        except (ValueError, KeyError) as e:
            logger.error(f"ノートブックの取得または解析中にエラーが発生しました: {e}")
            return [], None
    else:
        logger.error(f"ノートブックの取得中にAPIのレスポンスエラーが発生しました。: {response.status_code}, {response.text}")
        return [], None

"""分類名（セクション名）からセクションIDを取得"""
def get_notebook_and_section_ids(category_config, sender_email, section_name):
    result_list = []  # すべての結果を格納するリスト
    if sender_email in category_config:
        for item in category_config[sender_email]:
            # セクション名が一致するか確認
            if item['section']['section_name'] == section_name:
                result_list.append({
                    'notebook_name': item['notebook']['notebook_name'],
                    'notebook_id': item['notebook']['notebook_id'],
                    'section_id': item['section']['section_id']
                })

    logger.info(f'分類名からセクションIDを取得: {result_list}')

    # 一致した組み合わせがあれば返す。なければNoneを返す
    return result_list if result_list else None

"""OneNote用のデータを生成"""
def processed_onenote(processed_emails):
    result_list = []

    for email in processed_emails:
        subject = email.get('subject', "")
        sender = email.get('from_name', "")
        sender_email = email.get('from_email', "")
        to = ", ".join(email.get('to_recipients', []))
        cc = ", ".join(email.get('cc_recipients', []))
        priority_ai = email.get('priority_ai', "")
        received_date = email.get('received_date', "")
        web_link = email.get('web_link', "")
        summary = email.get('summary', "")
        body = email.get('body_text', "")
        attachments = email.get('attachments', [])
        references = email.get('internet_message_id', "")

        notebook_ids = email.get('notebook_id', [])
        notebook_names = email.get('notebook_name', [])
        category_ids = email.get('category_id', [])
        category_names = email.get('category_name', [])

        # 各セクションごとにタプルを追加
        for i in range(len(category_names)):
            notebook_id = notebook_ids[i] if i < len(notebook_ids) else ""
            notebook_name = notebook_names[i] if i < len(notebook_names) else "未設定"
            category_id = category_ids[i] if i < len(category_ids) else ""
            category_name = category_names[i] if i < len(category_names) else "その他"

            # 添付ファイルは最初のループのときだけ設定、それ以外は空
            # copied_attachments = copy.deepcopy(attachments) if i == 0 else []

            result_list.append((
                subject, sender, sender_email, to, cc,
                category_name, priority_ai, received_date, web_link,
                summary, body, attachments, references,
                notebook_id, notebook_name, category_id
            ))

    return result_list

"""OneNote用のHTMLコンテンツを生成"""
def generate_html(subject, sender, sender_email, to, cc, category, priority_ai, received_date, web_link, summary, body, attachments, references, now_date):
    # データがリストの場合は文字列に結合
    category = category or []
    references = references or []
    attachments = attachments or []
    
    if isinstance(category, list):
        category = ", ".join(category)  # カンマで結合
    if isinstance(references, list):
        references = ", ".join(references)  # カンマで結合
    if isinstance(attachments, list):
        attachment_list = "".join([
            f"<li>{html.escape(attachment.get('name', 'ファイル名未設定'))}</li>"
            for attachment in attachments
            if isinstance(attachment, dict)
        ])
    else:
        attachment_list = ""
        
    attachment_section = f"""
        <hr>
        <ul>{attachment_list}</ul>
    """ if attachments else "<p>添付ファイルなし</p>"

    # ファイルをエンコードして取得
    icon_base64 = utils.img_to_base64("static/img/mark_email_read_36dp_F19E39_FILL0_wght400_GRAD0_opsz40.png")

    # リンクアイコンの生成
    link_icon = f"""
        <a href="{web_link}" target="_blank" title="Outlook link">
            <img src="{icon_base64}" alt="Link Icon" style="width: 30px; height: 30px;" />
        </a>
    """ if web_link else "<span>No link available</span>"

    # 変数の事前エスケープ
    escaped_subject = html.escape(subject)
    escaped_sender = html.escape(sender)
    escaped_sender_email = html.escape(sender_email)
    escaped_to = html.escape(to)
    escaped_cc = html.escape(cc)
    escaped_category = html.escape(category)
    escaped_priority_ai = html.escape(priority_ai)
    escaped_received_date = html.escape(received_date)
    # escaped_web_link = html.escape(web_link)
    # escaped_summary = html.escape(summary).replace('\n', '<br>')
    escaped_body = html.escape(body).replace('\n', '<br>')

    # HTMLコンテンツの生成
    html_content = f"""
    <html lang="ja">
        <head>
            <title>{escaped_subject}</title>
            <meta name="created" content="{now_date}" />
        </head>
        <body style="margin-top: 30px; font-family: Meiryo UI, Arial, sans-serif;">
            <div>
                <table>
                    <tr><th>差出人:</th><td>{escaped_sender}</td></tr>
                    <tr><th>差出人Email:</th><td>{escaped_sender_email}</td></tr>
                    <tr><th>宛先:</th><td>{escaped_to}</td></tr>
                    <tr><th>CC:</th><td>{escaped_cc}</td></tr>
                    <tr><th>カテゴリー:</th><td>{escaped_category}</td></tr>
                    <tr><th>優先度:</th><td>{escaped_priority_ai}</td></tr>
                    <tr><th>受信日時:</th><td>{escaped_received_date}</td></tr>
                    <tr><th>Outlook:</th><td>{link_icon}</td></tr>
                    <tr><th>添付ファイル</th>
                        <td class="attachments">{attachment_section}</td>
                    </tr>
                </table>
                <hr>
                <div style="white-space: pre-wrap; font-size: 14px; line-height: 1.5;">
                    <p>{escaped_body}</p>
                </div>
            </div>
        </body>
    </html>
    """
    return html_content

"""OneNoteにページを作成する関数"""
def create_onenote_page(subject, sender, sender_email, to, cc, category, priority_ai, received_date, web_link, summary, body, attachments, references, access_token, user_id, selected_section_id, now_date):
    html_content = generate_html(subject, sender, sender_email, to, cc, category, priority_ai, received_date, web_link, summary, body, attachments, references, now_date)
    url = f"https://graph.microsoft.com/v1.0/users/{user_id}/onenote/sections/{selected_section_id}/pages"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/xhtml+xml"
    }

    # エンコード処理を追加
    html_content = html_content.encode('utf-8')

    # POSTリクエストを送信
    response = requests.post(url, headers=headers, data=html_content)
    
    # レスポンスの確認
    if response.status_code == 201:
        logger.info(f"✅ OneNoteページの作成成功: {subject}")
    else:
        logger.error(f"❌ ページの作成中にエラーが発生しました: {subject}, {response.status_code}, {response.text}")

"""OneNoteにメールを出力する関数"""
def main(processed_emails, user_access_token):
    user_id=os.getenv('user_mail')
    now_date, _ = utils.current_date()

    processed_data_list = processed_onenote(processed_emails)

    for data in processed_data_list:
        (
            subject, sender, sender_email, to, cc, category_name,
            priority_ai, received_date, web_link, summary, body,
            attachments, references, notebook_id, notebook_name, category_id
        ) = data

        # category_id が空の場合はスキップ
        if not category_id:
            logger.info(f"⏩ category_id 未設定のためスキップ: subject='{subject}' category_name='{category_name}'")
            continue

        logger.info(f"📝 OneNote 出力: notebook='{notebook_name}', section='{category_name}'")

        create_onenote_page(
            subject, sender, sender_email, to, cc, category_name, priority_ai,
            received_date, web_link, summary, body,
            attachments, [references], user_access_token, user_id,
            category_id, now_date
        )

    logger.info("✅ OneNote出力完了")