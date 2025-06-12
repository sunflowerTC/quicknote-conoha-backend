from datetime import datetime, timedelta

from celery_worker import celery
import logging
from logging_config import setup_logging

import utils
import outlook_mailbox

from db.db import db
from models import Job

from app import create_app

"""ロギングのセットアップ"""
logger = logging.getLogger("celery_access")

"""サブスクリプション更新ジョブ"""
@celery.task(name="tasks.graph_subscription_renewal")
def graph_subscription_renewal():
    app = create_app()

    try:
        logger.info("📡 Graph API サブスクリプションの有効性確認を開始")
        with app.app_context():
            from outlook_mailbox import ensure_subscription_valid
            ensure_subscription_valid()

            job = db.session.query(Job).filter(Job.task == "tasks.graph_subscription_renewal").first()
            if job and job.trigger == "interval":
                interval = timedelta(
                    hours=job.interval_hours or 0,
                    minutes=job.interval_minutes or 0
                )
                job.next_run_time = datetime.now() + interval
                job.updated_at = datetime.now()
                db.session.commit()
                logger.info(f"🕒 次回実行時刻を更新: {job.next_run_time} / 更新日時を更新: {job.updated_at}")
    except Exception as e:
        logger.error(f"❌ サブスクリプションの確認中にエラー: {e}")

        