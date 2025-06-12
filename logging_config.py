import os
import gzip
import shutil
import time
from datetime import datetime
import logging
from logging.handlers import TimedRotatingFileHandler
from logging.config import dictConfig

# IPアドレス用のフィルター
class IPAddressFilter(logging.Filter):
    def __init__(self, ip_address="Unknown IP"):
        super().__init__()
        self.ip_address = ip_address

    def filter(self, record):
        record.ip_address = getattr(record, "ip_address", self.ip_address)
        return True

# 正しいローテーション + 圧縮
class TimedCompressedRotatingFileHandler(TimedRotatingFileHandler):
    def doRollover(self):
        if self.stream:
            self.stream.close()
            self.stream = None

        if self.backupCount > 0:
            for s in self.getFilesToDelete():
                os.remove(s)

        # ローテーション先のファイル名（日付付き）
        time_tuple = time.localtime(self.rolloverAt - self.interval)
        dfn = self.rotation_filename(self.baseFilename + "." + time.strftime("%Y-%m-%d", time_tuple))
        self.rotate(self.baseFilename, dfn)

        # gzip圧縮
        if os.path.exists(dfn):
            with open(dfn, 'rb') as f_in, gzip.open(dfn + '.gz', 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
            os.remove(dfn)

        # 新しいログファイルを開き直す
        self.mode = 'a'
        self.stream = self._open()
        
        # 次回ロールオーバー時間を更新
        currentTime = int(time.time())
        newRolloverAt = self.computeRollover(currentTime)
        while newRolloverAt <= currentTime:
            newRolloverAt += self.interval
        self.rolloverAt = newRolloverAt

def getFilesToDelete(self):
    dirName, baseName = os.path.split(self.baseFilename)
    fileNames = os.listdir(dirName)
    prefix = baseName + "."
    suffix = ".gz"
    result = [os.path.join(dirName, f) for f in fileNames if f.startswith(prefix) and f.endswith(suffix)]
    result.sort()
    if len(result) <= self.backupCount:
        return []
    return result[:len(result) - self.backupCount]

# ロギングのセットアップ
def setup_logging(ip_address="Unknown IP", when='midnight', interval=1, backup_count=7):
    logs_dir = os.path.join(os.path.dirname(__file__), 'logs')
    os.makedirs(logs_dir, exist_ok=True)

    def log_path(name):
        return os.path.join(logs_dir, name)

    logging_config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'default': {
                'format': '[%(asctime)s] %(levelname)s in %(module)s [%(ip_address)s]: %(message)s',
                'datefmt': '%Y-%m-%d %H:%M:%S',
            },
        },
        'filters': {
            'ip_filter': {
                '()': IPAddressFilter,
                'ip_address': ip_address,
            },
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'formatter': 'default',
                'filters': ['ip_filter'],
            },
            # メインログ (全ログ)
            'mailsystem': {
                'class': 'logging_config.TimedCompressedRotatingFileHandler',
                'formatter': 'default',
                'filename': log_path('mailsystem.log'),
                'filters': ['ip_filter'],
                'when': when,
                'interval': interval,
                'backupCount': backup_count,
                'encoding': 'utf-8',
                'utc': False,
            },
            # Celery Worker 通常
            'celery_access': {
                'class': 'logging_config.TimedCompressedRotatingFileHandler',
                'formatter': 'default',
                'filename': log_path('celery_access.log'),
                'filters': ['ip_filter'],
                'when': when,
                'interval': interval,
                'backupCount': backup_count,
                'encoding': 'utf-8',
                'utc': False,
            },
            # Celery Worker エラー
            'celery_error': {
                'class': 'logging_config.TimedCompressedRotatingFileHandler',
                'formatter': 'default',
                'filename': log_path('celery_error.log'),
                'filters': ['ip_filter'],
                'when': when,
                'interval': interval,
                'backupCount': backup_count,
                'encoding': 'utf-8',
                'utc': False,
            },
            # Celery Beat 通常
            'celery_beat': {
                'class': 'logging_config.TimedCompressedRotatingFileHandler',
                'formatter': 'default',
                'filename': log_path('celery_beat.log'),
                'filters': ['ip_filter'],
                'when': when,
                'interval': interval,
                'backupCount': backup_count,
                'encoding': 'utf-8',
                'utc': False,
            },
            # Celery Beat エラー
            'celery_beat_error': {
                'class': 'logging_config.TimedCompressedRotatingFileHandler',
                'formatter': 'default',
                'filename': log_path('celery_beat_error.log'),
                'filters': ['ip_filter'],
                'when': when,
                'interval': interval,
                'backupCount': backup_count,
                'encoding': 'utf-8',
                'utc': False,
            },
        },
        'loggers': {
            'mailsystem': {
                'level': 'INFO',
                'handlers': ['console', 'mailsystem'],
                'propagate': False,
            },
            'celery_access': {
                'level': 'INFO',
                'handlers': ['console', 'celery_access', 'mailsystem'],
                'propagate': False,
            },
            'celery_error': {
                'level': 'ERROR',
                'handlers': ['console', 'celery_error', 'mailsystem'],
                'propagate': False,
            },
            'celery_beat': {
                'level': 'INFO',
                'handlers': ['console', 'celery_beat', 'mailsystem'],
                'propagate': False,
            },
            'celery_beat_error': {
                'level': 'ERROR',
                'handlers': ['console', 'celery_beat_error', 'mailsystem'],
                'propagate': False,
            },
        },
        'root': {
            'level': 'INFO',
            'handlers': ['console', 'mailsystem'],
        },
    }

    dictConfig(logging_config)
    return logging.getLogger('mailsystem')

# IP付きLoggerAdapter
def get_logger_with_ip(ip_address: str):
    logger = logging.getLogger("mailsystem")
    adapter = logging.LoggerAdapter(logger, {"ip_address": ip_address})
    return adapter
