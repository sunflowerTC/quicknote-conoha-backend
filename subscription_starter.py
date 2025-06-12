from app import create_app
from outlook_mailbox import ensure_subscription_valid

app = create_app()

with app.app_context():
    ensure_subscription_valid()