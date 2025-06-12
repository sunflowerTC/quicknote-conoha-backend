from db.db import db
from models.base_model import BaseModel

class ApiConfig(BaseModel):
    __tablename__ = 'api_configs'

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(255), nullable=False)
    client_secret = db.Column(db.String(255), nullable=False)
    tenant_id = db.Column(db.String(255), nullable=False)
    service_account_file = db.Column(db.String(255), nullable=False)
    organization = db.Column(db.String(255), nullable=False)
    secret_key = db.Column(db.String(255), nullable=False)
    webhook_enabled = db.Column(db.Boolean, nullable=False, default=False)

    def as_dict(self):
        return {
            "clientId": self.client_id or "",
            "clientSecret": self.client_secret or "",
            "tenantId": self.tenant_id or "",
            "serviceAccountFile": self.service_account_file or "",
            "organization": self.organization or "",
            "secretKey": self.secret_key or "",
            "webhookEnabled": self.webhook_enabled
        }