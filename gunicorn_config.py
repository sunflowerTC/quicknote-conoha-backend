bind = "0.0.0.0:5000"
workers = 2
threads = 4
timeout = 120
loglevel = "info"
accesslog = "/var/www/html/QuickNote/backend/logs/gunicorn_access.log"
errorlog = "/var/www/html/QuickNote/backend/logs/gunicorn_error.log"

# 改善点の追加
preload_app = True
max_requests = 1000
max_requests_jitter = 100
