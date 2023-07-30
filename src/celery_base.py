from celery import Celery
from time import sleep

broker_url = "amqp://guest:guest@rabbitmq:5672/"
redis_url = "redis://localhost"
app = Celery('tasks', broker=broker_url, backend=redis_url)