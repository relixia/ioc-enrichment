from celery_base import app
from models import Base, Session, IOC
from utilities import virustotal_save
import requests
import os
import json
from dotenv import load_dotenv

envs_path = os.path.join(os.path.dirname(__file__), "../envs/.env")
load_dotenv(dotenv_path=envs_path)

VIRUSTOTAL_API = os.getenv("VIRUSTOTAL_API")
IPINFO_API = os.getenv("IPINFO_API")


#AlienVault OTX: Ağ trafiğini izleyen ve zararlı davranışları algılayan açık tehdit istihbaratı platformu.


#----------------------------------------------------FOR URL IOCS-------------------------------------------------------------
# Kendi phishing servisim --> USOM, PhishTank, PhishStats, OpenPhish
# Google reklamlar: https://adstransparency.google.com/?region=anywhere
# URLhaus: Zararlı URL'leri içeren bir veritabanı.
# Shodan: İnternet üzerindeki cihazlar için açık port ve servis bilgisi sağlayan bir hizmet.
@app.task
def virustotal_url(user_url):
    print("virustotal scanning for url started")
    # VIRUSTOTAL POST API TO GET THE SCAN URL ID
    url = "https://www.virustotal.com/api/v3/urls"
    payload = {"url": user_url}
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API,
        "content-type": "application/x-www-form-urlencoded",
    }
    response = requests.post(url, data=payload, headers=headers)

    if response.status_code == 200:
        data = response.json()
        url_analysis_id = data["data"]["id"].split("-")[1]
        # VIRUSTOTAL GET API TO GET THE URL ANALYSIS REPORT BY USING THE SCAN URL ID
        url_rep = f"https://www.virustotal.com/api/v3/urls/{url_analysis_id}"
        headers_rep = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API}
        response_rep = requests.get(url_rep, headers=headers_rep)

        if response_rep.status_code == 200:
            virustotal_save(response=response_rep, ioc_name=user_url)
        return url_analysis_id
    else:
        return None

#----------------------------------------------------FOR DOMAIN IOCS-------------------------------------------------------------
@app.task
def virustotal_domain(user_domain):
    url = "https://www.virustotal.com/api/v3/domains/domain"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        virustotal_save(response=response, ioc_name=user_domain)


#----------------------------------------------------FOR IP ADDRESS IOCS-------------------------------------------------------------
# AbuseIPDB: Zararlı IP adresleri hakkında bilgi sunan bir hizmet.
# GreyNoise: İnternet gürültüsü ve zararlı IP adresleri arasındaki farkı belirleyen bir hizmet.
# https://api.iplocation.net
@app.task
def virustotal_ip(user_ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{user_ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        virustotal_save(response=response, ioc_name=user_ip)

@app.task
def ipinfo(user_ip):
    url = f"https://ipinfo.io/{user_ip}?token={IPINFO_API}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        ip_info = {
                "ip": data["ip"],
                "hostname": data["hostname"],
                "city": data["city"],
                "region": data["region"],
                "country": data["country"],
                "loc": data["loc"],
                "org": data["org"],
                "postal": data["postal"],
                "timezone": data["timezone"]
            }

        ip_info_json = json.dumps(ip_info)

        session = Session()
        url_row = session.query(IOC).filter_by(ioc=user_ip).first()

        if url_row:
            url_row.ipinfo = ip_info_json
            session.commit()
        session.close()


#----------------------------------------------------FOR FILES IOCS-------------------------------------------------------------
# URLhaus: Zararlı URL'leri içeren bir veritabanı.
@app.task
def virustotal_file(user_hash):
    url = f"https://www.virustotal.com/api/v3/files/{user_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        virustotal_save(response=response, ioc_name=user_hash)
