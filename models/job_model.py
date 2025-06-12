from db.db import db
from sqlalchemy import Column, Integer, String, DateTime
from models.base_model import BaseModel

class Job(BaseModel):
    __tablename__ = 'jobs'

    id = Column(Integer, primary_key=True, autoincrement=True)  # ✅ AUTO_INCREMENT 対応
    name = Column(String(255), nullable=False)  # ✅ ジョブ名
    task = Column(String(255), nullable=False)  # ✅ タスク名
    trigger = Column(String(255), nullable=False)  # ✅ 'interval' or 'cron'
    next_run_time = Column(DateTime, nullable=True)  # ✅ 次回実行時間
    interval_hours = Column(Integer, nullable=False, default=0)  # ✅ デフォルト値を設定
    interval_minutes = Column(Integer, nullable=False, default=0)  # ✅ デフォルト値を設定
    cron_hour = Column(Integer, nullable=True)  # ✅ `String(10)` → `Integer`
    cron_minute = Column(Integer, nullable=True)  # ✅ `String(10)` → `Integer`

    def __repr__(self):
        return f"<Job {self.id}: {self.name} (Next: {self.next_run_time})>"
