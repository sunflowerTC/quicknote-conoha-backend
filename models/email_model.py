import json
from datetime import datetime
from db.db import db
from models.base_model import BaseModel

class Email(BaseModel):
    __tablename__ = 'emails'

    # 保存用ID（internet_message_id優先、ない場合はGraph ID）
    id = db.Column(db.String(255), primary_key=True, comment="保存用ID（internet_message_id 優先。無ければGraph ID）")

    # Graph API メッセージID（常に取得できるID → 将来の再取得や更新時に使用可能）
    graph_id = db.Column(db.String(255), nullable=True, comment="Graph API メッセージID（メールのリソースID）")

    subject = db.Column(db.Text, nullable=True)
    from_name = db.Column(db.String(255), nullable=True)
    from_email = db.Column(db.String(255), nullable=True)
    sender_name = db.Column(db.String(255), nullable=True)
    sender_email = db.Column(db.String(255), nullable=True)

    to_recipients = db.Column(db.Text, nullable=True)  # JSON文字列で保存（配列対応）
    cc_recipients = db.Column(db.Text, nullable=True)
    bcc_recipients = db.Column(db.Text, nullable=True)

    received_date = db.Column(db.DateTime, nullable=True)
    sent_date = db.Column(db.DateTime, nullable=True)

    category_id = db.Column(db.Text, nullable=True)  # JSON文字列（配列対応）
    category_name = db.Column(db.Text, nullable=True)  # JSON文字列（配列対応）

    priority_ai = db.Column(db.String(255), nullable=True)

    has_attachments = db.Column(db.Boolean, nullable=False, default=False)
    attachments = db.Column(db.Text, nullable=True)  # JSON文字列（配列対応）

    # SMTPレベルのMessage ID（世界一意の可能性が高いが存在しない場合もある）
    internet_message_id = db.Column(db.String(255), nullable=True)

    # Conversation ID（スレッド管理用ID）
    conversation_id = db.Column(db.String(255), nullable=True)

    is_read = db.Column(db.Boolean, nullable=True)

    summary = db.Column(db.Text, nullable=True)
    body_preview = db.Column(db.Text, nullable=True)
    body_text = db.Column(db.Text, nullable=True)

    importance = db.Column(db.String(50), nullable=True)
    inference_classification = db.Column(db.String(50), nullable=True)

    web_link = db.Column(db.Text, nullable=True)

    categories = db.Column(db.Text, nullable=True)  # JSON文字列（配列対応）
    last_modified = db.Column(db.String(50), nullable=True)  # 最終更新日時（ISO8601形式）

    def __repr__(self):
        return f"<Email {self.id} Subject={self.subject}>"

    def as_dict(self):
        """カテゴリレポートで使うフィールドのみを辞書化"""
        try:
            categories = json.loads(self.category_name) if self.category_name else []
        except json.JSONDecodeError:
            categories = []
        return {
            "from_email": self.from_email,
            "category_name": categories,
        }
