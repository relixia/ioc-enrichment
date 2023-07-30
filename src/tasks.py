from celery_base import app

@app.task
def say_hello(name: str):
    return f"Hello {name}"