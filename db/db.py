from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# ✅ DB インスタンスを作成
db = SQLAlchemy()
migrate = Migrate()

def init_db(app):
    """
    アプリに DB と Migrate を初期化する
    """
    db.init_app(app)
    migrate.init_app(app, db)
