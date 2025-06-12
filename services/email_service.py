from db.db import db
from models import Email

from outlook_mailbox import extract_full_email_data
import json
from dateutil.parser import parse as parse_datetime

import logging
from logging_config import get_logger_with_ip
import utils

from sqlalchemy.exc import IntegrityError

"""ログファイル設定"""
logger = get_logger_with_ip(utils.get_local_ip())
# logger = logging.getLogger("mailsystem")

"""GraphデータからDBへ保存 (既存チェック付き)"""
def save_email_from_graph_data(full_email, access_token, change_type="created"):
    email_id = full_email.get('internet_message_id') or full_email.get('id')
    
    if not email_id:
        logger.error("❌ メールIDが存在しません")
        return

    # ✅ すでに存在するかチェック
    existing_email = db.session.query(Email).filter_by(id=email_id).first()
    if change_type == "created" and existing_email:
        logger.info(f"⏭️ メールID {email_id} はすでに存在するためDB保存をスキップ")
        return  # すでに登録済みなら何もせず終了

    try:
        email = Email(
            id=email_id,
            graph_id=full_email['graph_id'],
            subject=full_email['subject'],
            from_name=full_email['from_name'],
            from_email=full_email['from_email'],
            sender_name=full_email['sender_name'],
            sender_email=full_email['sender_email'],
            to_recipients=", ".join(full_email['to_recipients']),
            cc_recipients=", ".join(full_email['cc_recipients']),
            bcc_recipients=", ".join(full_email['bcc_recipients']),
            received_date=parse_datetime(full_email['received_date']) if full_email['received_date'] != 'Unknown' else None,
            category_id=json.dumps(full_email['category_id'], ensure_ascii=False),  # ✅
            category_name=json.dumps(full_email['category_name'], ensure_ascii=False),  # ✅
            priority_ai=full_email['priority_ai'],
            sent_date=parse_datetime(full_email['sent_date']) if full_email['sent_date'] != 'Unknown' else None,
            has_attachments=full_email['has_attachments'],
            attachments=json.dumps(full_email['attachments'], ensure_ascii=False),
            internet_message_id=full_email['internet_message_id'],
            conversation_id=full_email['conversation_id'],
            is_read=full_email['is_read'],
            summary=full_email['summary'],
            body_preview=full_email['body_preview'],
            body_text=full_email['body_text'],
            importance=full_email['importance'],
            inference_classification=full_email['inference_classification'],
            web_link=full_email['web_link'],
            categories=json.dumps(full_email['categories'], ensure_ascii=False),
            last_modified=full_email.get('last_modified')
        )
        db.session.merge(email)
        db.session.commit()
        logger.info(f"✅ メール {email_id} を正常に保存しました")

    except IntegrityError:
        db.session.rollback()
        logger.warning(f"⏭️ メールID {email_id} は既に存在します（重複保存を回避）")

    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ メール保存中に予期せぬエラーが発生しました: {str(e)}")
