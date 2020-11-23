from celery_app import app
from .scan import Scan

@app.task()
def task_scan(ip_range, rate):
    r = Scan(
        ip_range = ip_range,
        rate = rate,
        port = port
    )
    r.scan()