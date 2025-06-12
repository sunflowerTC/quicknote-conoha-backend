from db.db import db
from models.base_model import BaseModel

class Instruction(BaseModel):
    __tablename__ = 'instructions'

    id = db.Column(db.String(36), primary_key=True)
    request_date = db.Column(db.Date)
    email_received_date = db.Column(db.Date)
    instructions = db.Column(db.String(255))
    details = db.Column(db.Text)
    attached_files = db.Column(db.JSON)
    category = db.Column(db.String(50))
    storage_files = db.Column(db.JSON)  # MySQL 5.7+ 推奨
    complete_date = db.Column(db.Date)
    is_complete = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<Instruction id={self.id} request_date={self.request_date}>"

    def as_dict(self):
        return {
            "id": self.id,
            "requestDate": self.request_date.isoformat() if self.request_date else None,
            "emailReceivedDate": self.email_received_date.isoformat() if self.email_received_date else None,
            "instructions": self.instructions,
            "details": self.details,
            "attachedFiles": self.attached_files,
            "category": self.category,
            "storageFiles": self.storage_files,
            "completeDate": self.complete_date.isoformat() if self.complete_date else None,
            "isComplete": self.is_complete,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
