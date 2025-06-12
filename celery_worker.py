from celery import Celery
from config import Config
from scheduler import restore_jobs_from_db
from logging_config import setup_logging
import utils

import logging

# ✅ サーバーIP取得
server_ip = utils.get_local_ip() or "Unknown IP"

# ✅ ログのセットアップ
setup_logging(server_ip)

# ✅ celery用ロガーを取得
logger = logging.getLogger("celery_access")
logger.info("----- Celeryワーカー起動開始 -----")

# ✅ Celeryインスタンスを作成
def make_celery():
    celery = Celery(
        __name__,
        broker=Config.CELERY_BROKER_URL,
        backend=Config.RESULT_BACKEND,
        include=[
            "tasks",
            "webhook_tasks"
        ]
    )
    celery.conf.update(
        timezone="Asia/Tokyo",
        enable_utc=False,
        broker_connection_retry_on_startup=True
    )
    return celery

# ✅ Celery を作成
celery = make_celery()

# ✅ スケジュールの復元
restore_jobs_from_db(celery)

logger.info("----- Celeryワーカー準備完了 -----")

# ✅ Celery のエントリポイント
if __name__ == "__main__":
    logger.info("----- Celeryワーカーを開始 -----")
    celery.start()
