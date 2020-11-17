from celery import Celery

app = Celery("scanner", broker="amqp://broker//", backend="rpc://logging//")
app.autodiscover_tasks(
    [
        "alive.tasks",
        "scan.tasks",
    ],
    force = True
)
