from celery_app import app
from .alive import *

@app.task()
def task_alive_ping(ip_range):
    r = Alive(ip_range=ip_range)
    r.ping()