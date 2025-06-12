import os
import urllib.parse
from dotenv import load_dotenv
import logging
from logging_config import setup_logging
import utils

# .envファイルを読み込む
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
env_path = os.path.join(BASE_DIR, "mailsystem.env")

if not os.path.exists(env_path):
    raise FileNotFoundError(f"❌ エラー: `.env` ファイルが見つかりません。期待されるパス: {env_path}")
load_dotenv(env_path)

"""ログファイル設定"""
logger = logging.getLogger("mailsystem")

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your_secret_key')

    # MySQLの接続設定
    DB_USERNAME = os.getenv('DB_USERNAME', '')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = os.getenv('DB_PORT', '3306')
    DB_NAME = os.getenv('DB_NAME', '')

    # URLエンコード (パスワードに特殊文字が含まれる場合の対策)
    DB_PASSWORD_ENCODED = urllib.parse.quote_plus(DB_PASSWORD) if DB_PASSWORD else ''

    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{DB_USERNAME}:{DB_PASSWORD_ENCODED}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ✅ Celery の設定（APScheduler から移行する場合）
    CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    RESULT_BACKEND = os.getenv('RESULT_BACKEND', 'redis://localhost:6379/0')

    # 🔹 環境変数のバリデーション（詳細を出力）
    missing_vars = []
    for var in ["DB_USERNAME", "DB_PASSWORD", "DB_NAME"]:
        if not os.getenv(var, ''):
            missing_vars.append(var)

    if missing_vars:
        logger.warning(f"⚠️ 環境変数（.env）が正しく設定されていない可能性があります: {', '.join(missing_vars)}")