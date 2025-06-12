from flask import Blueprint, jsonify, request, session
from scripts.import_emails import load_emails_from_json
import os
import re
import json
import base64
import requests
import logging

from dotenv import load_dotenv

from werkzeug.utils import secure_filename
from decorators import login_required_api
import utils

from db.db import db
from models import Account

email_bp = Blueprint('email_bp', __name__)

"""mailsystem.envファイルを読み込む"""
load_dotenv("mailsystem.env")

"""ログファイル設定"""
logger = logging.getLogger("mailsystem")

"""環境変数読み込み"""
MAIL_API_KEY = os.getenv("MAIL_API_KEY")
GRAPH_SENDER = os.getenv("GRAPH_SENDER")
MAIL_RECEIVER = os.getenv("MAIL_RECEIVER")

@email_bp.route('/api/emails/import', methods=['POST'])
@login_required_api
def import_emails():
    try:
        json_path = os.path.join(os.path.dirname(__file__), '..', 'outlook_emails.json')
        load_emails_from_json(json_path)
        return jsonify({'message': '✅ メールデータの取り込みに成功しました'}), 200
    except Exception as e:
        return jsonify({'message': f'❌ エラーが発生しました: {str(e)}'}), 500

@email_bp.route("/api/send_instruction_mail", methods=["POST"])
@login_required_api
def send_instruction_mail():
    # APIキー認証
    api_key = request.headers.get("X-API-KEY")
    if api_key != MAIL_API_KEY:
        logger.error("❌ 不正なAPIキーでアクセスされました")
        return jsonify({"error": "Unauthorized"}), 401

    try:
        subject = request.form.get("subject")
        instructions_raw = request.form.get("instructions")
        mail_to_raw = request.form.get("mail_to_list")

        if not subject or not instructions_raw :
            return jsonify({"error": "Invalid request (missing data)"}), 400

        logger.info(f"📥 instructions_raw = {instructions_raw}")

        instructions = json.loads(instructions_raw)
        mail_to_list = json.loads(mail_to_raw or "[]")

    except json.JSONDecodeError as e:
        logger.error(f"❌ JSON decode failed: {e}")
        return jsonify({"error": "JSON decode failed"}), 400

    # ログインユーザーのメールアドレスを取得（Flaskのgやsessionから取得する例）
    user_id = session.get("user_id")
    user = Account.query.get(user_id)

    if not user or not user.email:
        return jsonify({"error": "送信者メールアドレスが取得できません"}), 400

    reply_to_email = user.email

    # ✅ 添付ファイルを Graph API 形式で整形
    MAX_FILE_SIZE = 4 * 1024 * 1024  # 4MB
    attachments = []
    for f in request.files.getlist("files"):
        try:
            filename = secure_filename(f.filename)
            content = f.read()
            if len(content) > MAX_FILE_SIZE:
                logger.warning(f"❌ ファイルサイズ超過: {filename}")
                return jsonify({"error": f"ファイル '{filename}' は 4MB を超えています"}), 400

            # Base64エンコードしてGraph API形式に変換
            content_b64 = base64.b64encode(content).decode("utf-8")
            attachments.append({
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": filename,
                "contentType": f.mimetype,
                "contentBytes": content_b64
            })
        except Exception as e:
            logger.warning(f"📎 添付ファイルエラー: {str(e)}")

    # メール本文作成
    body_lines = ["【指示書内容】\n"]
    for inst in instructions:
        body_lines.append(f"・依頼日: {inst.get('requestDate') or '未設定'}")
        body_lines.append(f"・メール受信日: {inst.get('emailReceivedDate') or '未設定'}")
        body_lines.append(f"・指示内容: {inst.get('instructions') or '未設定'}")
        body_lines.append(f"・詳細指示: {inst.get('details') or '未設定'}")

        # 添付ファイルはリスト想定
        attached_files = inst.get("attachedFiles") or []
        if isinstance(attached_files, list):
            attached_files_text = ", ".join(attached_files) if attached_files else "なし"
        else:
            attached_files_text = attached_files
        body_lines.append(f"・添付ファイル: {attached_files_text}")

        body_lines.append(f"・PDF区分: {inst.get('category') or '未設定'}")

        # 保管ファイルもリスト想定
        storage_files = inst.get("storageFiles") or []
        if isinstance(storage_files, list):
            storage_files_text = ", ".join(storage_files) if storage_files else "なし"
        else:
            storage_files_text = storage_files

        body_lines.append(f"・保管ファイル: {storage_files_text}")

        body_lines.append(f"・結了日: {inst.get('completeDate') or '未設定'}")
        body_lines.append(f"・結了確認: {'結了' if inst.get('isComplete') else '未了'}")
        body_lines.append("-" * 100)

    body_text = "\n".join(body_lines)

    # ✅ 送信者氏名を追加
    body_text += "\n\n【送信者】\n"
    body_text += f"{user.last_name or ''} {user.first_name or ''}".strip()

    # アクセストークン取得
    access_token = utils.create_access_token()
    if not access_token:
        return jsonify({"error": "アクセストークン取得失敗"}), 500

    # 宛先リスト（指定がなければ MAIL_RECEIVER を使う）
    if mail_to_list and isinstance(mail_to_list, list):
        EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

        filtered_list = []
        for addr in mail_to_list:
            # ここで文字列だけを対象にする（dictだった場合はスキップ or 文字列抽出）
            if isinstance(addr, dict) and "emailAddress" in addr and "address" in addr["emailAddress"]:
                email = addr["emailAddress"]["address"]
            else:
                email = addr

            if isinstance(email, str) and email.strip() and EMAIL_REGEX.match(email.strip()):
                filtered_list.append(email.strip())

        if filtered_list:
            to_recipients = [{"emailAddress": {"address": addr}} for addr in filtered_list]
        else:
            to_recipients = [{"emailAddress": {"address": MAIL_RECEIVER}}]
    else:
        to_recipients = [{"emailAddress": {"address": MAIL_RECEIVER}}]

    payload = {
        "message": {
            "subject": subject,
            "body": {
                "contentType": "Text",
                "content": body_text
            },
            "toRecipients": to_recipients,
                    # ✅ 追加: Reply-To を指定（ログインユーザーのメールアドレス）
            "replyTo": [
                {"emailAddress": {"address": reply_to_email}}
            ],
            # ✅ （オプション）追加: From表示名を指定（ログインユーザーのユーザーIDなど）
            "from": {
                "emailAddress": {
                    "address": GRAPH_SENDER,
                    "name": f"{user.userid}（システム）"
                }
            },
            "attachments": attachments
        }
    }

    # リクエスト送信
    try:
        response = requests.post(
            f"https://graph.microsoft.com/v1.0/users/{GRAPH_SENDER}/sendMail",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            },
            json=payload
        )
    except Exception as e:
        logger.error(f"❌ リクエストエラー: {str(e)}")
        return jsonify({"error": f"リクエストエラー: {str(e)}"}), 500

    if response.status_code == 202:
        logger.info(f"✅ メール送信成功 → {[r['emailAddress']['address'] for r in to_recipients]}")
        return jsonify({"message": "メール送信成功"}), 200
    else:
        logger.error(f"❌ メール送信失敗: {response.text}")
        return jsonify({"error": f"送信失敗: {response.text}"}), 500