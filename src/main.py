from fastapi import FastAPI
from celery_base import app
from tasks import say_hello

app_fastapi = FastAPI()

@app_fastapi.get("/search")
async def search():
    return {"message": "Hello World!"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app_fastapi, host="0.0.0.0", port=8000)
