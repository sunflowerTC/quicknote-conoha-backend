import logging
from logging_config import setup_logging
import utils
from celery.schedules import crontab
from datetime import datetime, timedelta
from db.db import db
from models import Job

"""ログファイル設定"""
logger = logging.getLogger("celery_beat")

def restore_jobs_from_db(celery):
    from app import app
    logger.info("🔄 データベースからスケジュールを復元中...")

    try:
        schedules = {}

        with app.app_context():
            jobs = db.session.query(Job).all()

            for job in jobs:
                try:
                    schedule_id = f"job_{job.id}"
                    task_name = job.task or "tasks.graph_subscription_renewal"

                    if job.trigger == "interval":
                        interval_time = timedelta(
                            hours=job.interval_hours or 0,
                            minutes=job.interval_minutes or 0
                        )

                        schedules[schedule_id] = {
                            "task": task_name,
                            "schedule": interval_time
                        }

                    logger.info(f"✅ ジョブ復元: {job.id} - 次回実行: {job.next_run_time} - タスク: {task_name}")

                except Exception as e:
                    logger.error(f"⚠️ ジョブ復元エラー: {job.id}, {e}")

        celery.conf.beat_schedule.clear()
        celery.conf.beat_schedule = schedules
        celery.conf.update()

        logger.info(f"✅ スケジュールの復元が完了しました！ ({len(jobs)} 件)")
        logger.info(f"📌 Celery Beat に登録されたジョブ: {list(celery.conf.beat_schedule.keys())}")

    except Exception as e:
        logger.error(f"❌ スケジュール復元時のエラー: {e}")

"""DBからジョブを取得し、Celery Beat のスケジュールに適用"""
def load_schedules(celery):
    from app import app
    logger.info("📌 スケジュールをロード中...")

    try:
        schedules = {}

        with app.app_context():
            jobs = db.session.query(Job).all()

            for job in jobs:
                try:
                    schedule_id = f"job_{job.id}"
                    task_name = job.task or "tasks.graph_subscription_renewal"

                    if job.trigger == "interval":
                        interval_time = timedelta(
                            hours=job.interval_hours or 0,
                            minutes=job.interval_minutes or 0
                        )

                        schedules[schedule_id] = {
                            "task": task_name,
                            "schedule": interval_time
                        }

                    logger.info(f"✅ ジョブ登録: {job.id} - タスク: {task_name}")

                except Exception as e:
                    logger.error(f"⚠️ ジョブ登録エラー: {job.id}, {e}")

        celery.conf.beat_schedule.clear()
        celery.conf.beat_schedule = schedules
        celery.conf.update()

        logger.info(f"✅ スケジュール設定完了: {len(schedules)} 件のジョブが適用されました。")

    except Exception as e:
        logger.error(f"❌ スケジュールロード時のエラー: {e}")

