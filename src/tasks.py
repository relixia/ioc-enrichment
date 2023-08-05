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
ABUSEIPDB_API = os.getenv("ABUSEIPDB_API")
GREYNOISE_API = os.getenv("GREYNOISE_API")
OPSWAT_API = os.getenv("OPSWAT_API")


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

@app.task
def abuseipdb(user_ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "ipAddress": user_ip,
        "maxAgeInDays": 90,
        "verbose": True
    }
    headers = {
        "Key": ABUSEIPDB_API,
        "Accept": "application/json"
    }
    response = requests.get(url, params=params, headers=headers)
    if response.status_code == 200:
        data = response.json()
        abuse_info = {
            "ip": data["data"]["ipAddress"],
            "is_public": data["data"]["isPublic"],
            "ip_version": data["data"]["ipVersion"],
            "is_whitelisted": data["data"]["isWhitelisted"],
            "abuse_confidence_score": data["data"]["abuseConfidenceScore"],
            "country_code": data["data"]["countryCode"],
            "usage_type": data["data"]["usageType"],
            "isp": data["data"]["isp"],
            "domain": data["data"]["domain"],
            "hostnames": data["data"]["hostnames"],
            "total_reports": data["data"]["totalReports"],
            "num_distinct_users": data["data"]["numDistinctUsers"],
            "last_reported_at": data["data"]["lastReportedAt"]
        }

        abuse_info_json = json.dumps(abuse_info)

        session = Session()
        url_row = session.query(IOC).filter_by(ioc=user_ip).first()

        if url_row:
            url_row.abuseipdb = abuse_info_json
            session.commit()
        session.close()
    
@app.task
def greynoise(user_ip):
    url = f"https://api.greynoise.io/v3/community/{user_ip}"
    headers = {
        "accept": "application/json",
        "key": GREYNOISE_API
    }
    response = requests.get(url, headers=headers)
    
    data = response.json()
    if "classification" in data:
        greynoise_info = {
        "ip": data["ip"],
        "noise": data["noise"],
        "riot": data["riot"],
        "classification": data["classification"],
        "name": data["name"],
        "link": data["link"],
        "last_seen": data["last_seen"],
        "message": data["message"]
        }
    else:
        greynoise_info = {
            "ip": data["ip"],
            "noise": data["noise"],
            "riot": data["riot"],
            "message": data["message"]
        }

    greynoise_info_json = json.dumps(greynoise_info)

    session = Session()
    url_row = session.query(IOC).filter_by(ioc=user_ip).first()

    if url_row:
        url_row.greynoise = greynoise_info_json
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

@app.task
def opswat(user_hash):
    url = f"https://api.metadefender.com/v5/threat-intel/file-analysis/{user_hash}"
    headers = {
        "apikey": OPSWAT_API
    }

    response = requests.request("GET", url, headers=headers)

    if response.status_code == 200:
        data = response.json()

        file_info = data.get("file_info", {})
        last_av_scan = data.get("last_av_scan", {})

        opswat_info = {
            "md5": data.get("md5"),
            "sha1": data.get("sha1"),
            "sha256": data.get("sha256"),
            "file_size": file_info.get("file_size"),
            "file_type": file_info.get("file_type"),
            "file_type_category": file_info.get("file_type_category"),
            "file_type_description": file_info.get("file_type_description"),
            "file_type_extension": file_info.get("file_type_extension"),
            "trust_factor": data.get("trust_factor"),
            "malware_families": last_av_scan.get("malware_families", []),
            "malware_types": last_av_scan.get("malware_types", []),
            "platforms": last_av_scan.get("platforms", []),
            "scan_all_result_i": last_av_scan.get("scan_all_result_i"),
            "standard_threat_name": last_av_scan.get("standard_threat_name"),
            "start_time": last_av_scan.get("start_time"),
            "sub_platform": last_av_scan.get("sub_platform"),
            "total_avs": last_av_scan.get("total_avs"),
            "total_detected_avs": last_av_scan.get("total_detected_avs"),
            "total_time": last_av_scan.get("total_time")
        }

        opswat_info_json = json.dumps(opswat_info)

        session = Session()
        url_row = session.query(IOC).filter_by(ioc=user_hash).first()

        if url_row:
            url_row.opswat = opswat_info_json
            session.commit()
        session.close()

@app.task
def opswat_file_reputation(user_hash):
    url = f"https://api.metadefender.com/v5/threat-intel/av-file-reputation/{user_hash}"
    headers = {
        "apikey": OPSWAT_API,
        "extended": "1"
    }
    response = requests.request("GET", url, headers=headers)

    if response.status_code == 200:
        data = response.json()

        file_info = data.get("file_info", {})

        opswat_info = {
            "md5": data.get("md5"),
            "sha1": data.get("sha1"),
            "sha256": data.get("sha256"),
            "reputation": data.get("reputation"),
            "reputation_i": data.get("reputation_i"),
            "file_size": file_info.get("file_size"),
            "file_type": file_info.get("file_type"),
            "file_type_category": file_info.get("file_type_category"),
            "file_type_description": file_info.get("file_type_description"),
            "file_type_extension": file_info.get("file_type_extension"),
            "total_avs": data.get("total_avs"),
            "av_detection_count": data.get("av_detection_count"),
            "av_detection_percentage": data.get("av_detection_percentage"),
            "confidence_level": data.get("confidence_level"),
            "risk_level": data.get("risk_level"),
            "standard_threat_name": data.get("standard_threat_name"),
            "malware_families": data.get("malware_families", []),
            "malware_threat_names": data.get("malware_threat_names", []),
            "malware_types": data.get("malware_types", []),
            "platforms": data.get("platforms", [])
        }

        opswat_info_json = json.dumps(opswat_info)

        session = Session()
        url_row = session.query(IOC).filter_by(ioc=user_hash).first()

        if url_row:
            url_row.opswat_file_reputation = opswat_info_json
            session.commit()
        else:
            # Hash doesn't exist in the database, create a new row
            url_row = IOC(ioc=user_hash, ioc_type="Hash", opswat_file_reputation=opswat_info_json)
            session.add(url_row)
            session.commit()

        session.close()
