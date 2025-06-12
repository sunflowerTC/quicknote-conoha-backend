import json
from datetime import datetime
from models import Email
from db.db import db
from flask import current_app 

def parse_datetime(value):
    if value:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    return None

def load_emails_from_json(json_path):
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for item in data:
        email = Email(
            id=item["id"],
            subject=item.get("subject"),
            from_name=item.get("from_name"),
            from_email=item.get("from_email"),
            sender_name=item.get("sender_name"),
            sender_email=item.get("sender_email"),
            to_recipients=json.dumps(item.get("to_recipients", []), ensure_ascii=False),
            cc_recipients=json.dumps(item.get("cc_recipients", []), ensure_ascii=False),
            bcc_recipients=json.dumps(item.get("bcc_recipients", []), ensure_ascii=False),
            received_date=parse_datetime(item.get("received_date")),
            sent_date=parse_datetime(item.get("sent_date")),
            category_id=json.dumps(item.get("category_id", []), ensure_ascii=False),
            category_name=json.dumps(item.get("category_name", []), ensure_ascii=False),
            priority_ai=item.get("priority_ai"),
            has_attachments=item.get("has_attachments", False),
            attachments=json.dumps(item.get("attachments", []), ensure_ascii=False),
            internet_message_id=item.get("internet_message_id"),
            conversation_id=item.get("conversation_id"),
            is_read=item.get("is_read"),
            summary=item.get("summary"),
            body_preview=item.get("body_preview"),
            body_text=item.get("body_text"),
            importance=item.get("importance"),
            inference_classification=item.get("inference_classification"),
            web_link=item.get("web_link"),
            categories=json.dumps(item.get("categories", []), ensure_ascii=False)
        )
        db.session.merge(email)  # 既存の id があれば更新
    db.session.commit()
    print(f"{len(data)} 件のメールを取り込みました。")

if __name__ == "__main__":
    with app.app_context():
        load_emails_from_json("backend/outlook_emails.json")
