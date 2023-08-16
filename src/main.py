import os

import jinja2
import uvicorn
from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from celery_base import app
from enums import InputType
from enums_ops import input_task_mapping
from models import IOC, Base, Session, engine
from utilities import calculate_file_hash, check_input_type, ioc_save_db

app_fastapi = FastAPI()

templates = Jinja2Templates(directory="templates")
templates.env.globals.update(enumerate=enumerate)
app_fastapi.mount("/static", StaticFiles(directory="templates/static"), name="static")


@app_fastapi.get("/", response_class=HTMLResponse)
async def read_item(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app_fastapi.post("/search", response_class=HTMLResponse)
async def search(
    request: Request, input_text: str = Form(None), input_file: UploadFile = File(None)
):
    input_type = None
    sha256_hash = None

    if input_text is not None:
        input_type = check_input_type(input_text)
        ioc_save_db(input_text, input_type)
        tasks_to_dispatch = input_task_mapping[input_type]
        for task in tasks_to_dispatch:
            task.delay(input_text)

    elif input_file is not None:
        file_content = await input_file.read()
        file_name = input_file.filename
        sha256_hash = calculate_file_hash(file_content)
        ioc_save_db(sha256_hash, "InputType.FILE_HASH")

        tasks_to_dispatch = input_task_mapping[InputType.FILE_HASH]
        for task in tasks_to_dispatch:
            task.delay(sha256_hash)

    # Fetch data from the database for the input_text or sha256_hash
    session = Session()
    if input_text:
        result = session.query(IOC).filter_by(ioc=input_text).first()
    elif sha256_hash:
        result = session.query(IOC).filter_by(ioc=sha256_hash).first()
    else:
        result = None
    session.close()

    # Generate the list of services dynamically
    services = [
        column.name
        for column in IOC.__table__.columns
        if column.name != "ioc" and column.name != "ioc_type"
    ]

    return templates.TemplateResponse(
        "result.html",
        {
            "request": request,
            "input_text": input_text,
            "input_type": input_type,
            "sha256_hash": sha256_hash,
            "result": result,
            "services": services,
            "results": result,
        },
    )


if __name__ == "__main__":
    Base.metadata.create_all(engine)
    uvicorn.run(app_fastapi, host="0.0.0.0", port=8000)
