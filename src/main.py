import os
from fastapi import FastAPI, Request, Form, File, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from celery_base import app
from tasks import say_hello
import uvicorn
import jinja2
from utilities import check_input_type, calculate_file_hash
from fastapi.staticfiles import StaticFiles


app_fastapi = FastAPI()

templates = Jinja2Templates(directory="templates")
app_fastapi.mount("/static", StaticFiles(directory="templates/static"), name="static")


@app_fastapi.get("/", response_class=HTMLResponse)
async def read_item(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app_fastapi.post("/search", response_class=HTMLResponse)
async def search(
    request: Request,
    input_text: str = Form(None),
    input_file: UploadFile = File(None)
):
    input_type = None
    sha256_hash = None

    if input_text is not None:
        # Text form submission
        input_type = check_input_type(input_text)
        print("Input Text:", input_text)
        print("Input Type:", input_type)
    elif input_file is not None:
        # File form submission
        file_content = await input_file.read()
        file_name = input_file.filename
        print("Uploaded File Name:", file_name)

        # Calculate the file hash
        sha256_hash = calculate_file_hash(file_content)
        print("SHA-256 Hash:", sha256_hash)
    else:
        # Neither input_text nor input_file provided, set sha256_hash to None
        sha256_hash = None

    # Return the processed result back to the frontend
    return templates.TemplateResponse(
        "result.html",
        {
            "request": request,
            "input_text": input_text,
            "input_type": input_type,
            "sha256_hash": sha256_hash
        }
    )


if __name__ == "__main__":
    uvicorn.run(app_fastapi, host="0.0.0.0", port=8000)
