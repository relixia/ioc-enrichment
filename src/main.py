import os
from fastapi import FastAPI, Request, Form, File, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from celery_base import app
from tasks import virustotal_url, virustotal_file, virustotal_ip, virustotal_domain, ipinfo, abuseipdb, greynoise, opswat, opswat_file_reputation, kaspersky_file, kaspersky_ip, kaspersky_domain, kaspersky_url, hybridana_file, urlscanio, criminalip_ip, criminalip_domain, cloudflare_email, cloudflare_ip, iplocation, urlhaus, phishtank, usom, openphish, shodan, ipqualityscore, ipqualityscore_email, abstract_email  
import uvicorn
import jinja2
from utilities import check_input_type, calculate_file_hash, ioc_save_db
from fastapi.staticfiles import StaticFiles
from models import Base, Session, IOC, engine


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
        input_type = check_input_type(input_text)
        print("Input Text:", input_text)
        print("Input Type:", input_type)
        ioc_save_db(input_text, input_type)
        if input_type == "URL":
            #virustotal_url.delay(input_text)
            #kaspersky_url.delay(input_text)
            #urlscanio.delay(input_text)
            #cloudflare_email.delay(input_text)
            #urlhaus.delay(input_text)
            #phishtank.delay(input_text)
            #openphish.delay(input_text)
            ipqualityscore.delay(input_text)
        elif input_type == "Domain":
            #virustotal_domain.delay(input_text)
            #kaspersky_domain.delay(input_text)
            #criminalip_domain.delay(input_text)
            #cloudflare_email.delay(input_text)
            usom.delay(input_text)
            ipqualityscore.delay(input_text)
        elif input_type == "File Hash":
            #virustotal_file.delay(input_text)
            #opswat.delay(input_text)
            #opswat_file_reputation.delay(input_text)
            #kaspersky_file.delay(input_text)
            hybridana_file.delay(input_text)
            cloudflare_email.delay(input_text)
        elif input_type == "IP Address":
            #virustotal_ip.delay(input_text)
            #ipinfo.delay(input_text)
            #abuseipdb.delay(input_text)
            #greynoise.delay(input_text)
            #kaspersky_ip.delay(input_text)
            #criminalip_ip.delay(input_text)
            #cloudflare_ip.delay(input_text)
            #cloudflare_email.delay(input_text)
            iplocation.delay(input_text)
            shodan.delay(input_text)
        elif input_type == "Email Address":
            ipqualityscore_email.delay(input_text)
            abstract_email.delay(input_text)

    elif input_file is not None:
        file_content = await input_file.read()
        file_name = input_file.filename
        print("Uploaded File Name:", file_name)

        sha256_hash = calculate_file_hash(file_content)
        print("SHA-256 Hash:", sha256_hash)
        ioc_save_db(sha256_hash, "File/File Hash")
        #virustotal_file.delay(sha256_hash)
        #opswat.delay(sha256_hash)
        opswat_file_reputation.delay(sha256_hash)
        kaspersky_file.delay(sha256_hash)
        hybridana_file.delay(sha256_hash)
        cloudflare_email.delay(sha256_hash)
    else:
        sha256_hash = None

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
    Base.metadata.create_all(engine)
    uvicorn.run(app_fastapi, host="0.0.0.0", port=8000)
