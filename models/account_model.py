from db.db import db
from sqlalchemy.dialects.mysql import ENUM
from models.base_model import BaseModel

class Account(BaseModel):
    __tablename__ = 'accounts'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    userid = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)
    totp_secret = db.Column(db.String(32), nullable=False)
    role = db.Column(ENUM('admin', 'user', 'guest'), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)
    first_name = db.Column(db.String(30), nullable=False)

    def __repr__(self):
        return f"<Account {self.userid}>"
