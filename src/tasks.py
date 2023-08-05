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
KASPERSKY_API = os.getenv("KASPERSKY_API")


#AlienVault OTX: Ağ trafiğini izleyen ve zararlı davranışları algılayan açık tehdit istihbaratı platformu.


#----------------------------------------------------FOR URL IOCS-------------------------------------------------------------
# Kendi phishing servisim --> USOM, PhishTank, PhishStats, OpenPhish
# Google reklamlar: https://adstransparency.google.com/?region=anywhere
# URLhaus: Zararlı URL'leri içeren bir veritabanı.
# Shodan: İnternet üzerindeki cihazlar için açık port ve servis bilgisi sağlayan bir hizmet.
@app.task
def virustotal_url(user_url):
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

@app.task
def kaspersky_url(user_url):
    url = f"https://opentip.kaspersky.com/api/v1/search/url?request={user_url}"
    headers = { 
        "x-api-key": KASPERSKY_API
    }
    response = requests.request("GET", url, headers=headers)

    if response.status_code == 200:
        data = response.json()

        url_general_info = data.get("UrlGeneralInfo", {})
        url_domain_whois_info = data.get("UrlDomainWhoIs", {})

        kaspersky_url_info = {
            "url": url_general_info.get("Url"),
            "host": url_general_info.get("Host"),
            "ipv4_count": url_general_info.get("Ipv4Count"),
            "files_count": url_general_info.get("FilesCount"),
            "categories": url_general_info.get("Categories"),
            "categories_with_zone": [
                {
                    "name": category.get("Name"),
                    "zone": category.get("Zone")
                }
                for category in url_general_info.get("CategoriesWithZone", [])
            ],
            "domain_name": url_domain_whois_info.get("DomainName"),
            "created": url_domain_whois_info.get("Created"),
            "updated": url_domain_whois_info.get("Updated"),
            "expires": url_domain_whois_info.get("Expires"),
            "name_servers": url_domain_whois_info.get("NameServers"),
            "contacts": [
                {
                    "contact_type": contact.get("ContactType"),
                    "name": contact.get("Name"),
                    "organization": contact.get("Organization"),
                    "address": contact.get("Address"),
                    "city": contact.get("City"),
                    "state": contact.get("State"),
                    "postal_code": contact.get("PostalCode"),
                    "country_code": contact.get("CountryCode"),
                    "phone": contact.get("Phone"),
                    "fax": contact.get("Fax"),
                    "email": contact.get("Email")
                }
                for contact in url_domain_whois_info.get("Contacts", [])
            ],
            "registrar": {
                "info": url_domain_whois_info.get("Registrar", {}).get("Info"),
                "iana_id": url_domain_whois_info.get("Registrar", {}).get("IanaId")
            },
            "domain_status": url_domain_whois_info.get("DomainStatus"),
            "registration_organization": url_domain_whois_info.get("RegistrationOrganization")
        }

        kaspersky_url_info_json = json.dumps(kaspersky_url_info)

        session = Session()
        url_row = session.query(IOC).filter_by(ioc=user_url).first()

        if url_row:
            url_row.kaspersky = kaspersky_url_info_json
            session.commit()
        session.close()

#----------------------------------------------------FOR DOMAIN IOCS-------------------------------------------------------------
@app.task
def virustotal_domain(user_domain):
    url = f"https://www.virustotal.com/api/v3/domains/{user_domain}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        virustotal_save(response=response, ioc_name=user_domain)

@app.task
def kaspersky_domain(user_domain):
    url = f"https://opentip.kaspersky.com/api/v1/search/domain?request={user_domain}"
    headers = { 
        "x-api-key": KASPERSKY_API
    }
    response = requests.request("GET", url, headers=headers)

    if response.status_code == 200:
        data = response.json()

        domain_general_info = data.get("DomainGeneralInfo", {})
        domain_whois_info = data.get("DomainWhoIsInfo", {})

        kaspersky_domain_info = {
            "domain": domain_general_info.get("Domain"),
            "files_count": domain_general_info.get("FilesCount"),
            "urls_count": domain_general_info.get("UrlsCount"),
            "hits_count": domain_general_info.get("HitsCount"),
            "ipv4_count": domain_general_info.get("Ipv4Count"),
            "categories": domain_general_info.get("Categories"),
            "categories_with_zone": [
                {
                    "name": category.get("Name"),
                    "zone": category.get("Zone")
                }
                for category in domain_general_info.get("CategoriesWithZone", [])
            ],
            "domain_name": domain_whois_info.get("DomainName"),
            "created": domain_whois_info.get("Created"),
            "updated": domain_whois_info.get("Updated"),
            "expires": domain_whois_info.get("Expires"),
            "name_servers": domain_whois_info.get("NameServers"),
            "contacts": [
                {
                    "contact_type": contact.get("ContactType"),
                    "organization": contact.get("Organization"),
                    "state": contact.get("State"),
                    "country_code": contact.get("CountryCode")
                }
                for contact in domain_whois_info.get("Contacts", [])
            ],
            "registrar": {
                "info": domain_whois_info.get("Registrar", {}).get("Info"),
                "iana_id": domain_whois_info.get("Registrar", {}).get("IanaId")
            },
            "domain_status": domain_whois_info.get("DomainStatus"),
            "registration_organization": domain_whois_info.get("RegistrationOrganization")
        }

        kaspersky_domain_info_json = json.dumps(kaspersky_domain_info)

        session = Session()
        url_row = session.query(IOC).filter_by(ioc=user_domain).first()

        if url_row:
            url_row.kaspersky = kaspersky_domain_info_json
            session.commit()
        session.close()    

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

@app.task
def kaspersky_ip(user_ip):
    url = f"https://opentip.kaspersky.com/api/v1/search/ip?request={user_ip}"
    headers = { 
        "x-api-key": KASPERSKY_API
    }
    response = requests.request("GET", url, headers=headers)

    if response.status_code == 200:
        data = response.json()

        ip_general_info = data.get("IpGeneralInfo", {})
        ip_whois = data.get("IpWhoIs", {})

        kaspersky_ip_info = {
            "ip": ip_general_info.get("Ip"),
            "status": ip_general_info.get("Status"),
            "country_code": ip_general_info.get("CountryCode"),
            "asn": [
                {
                    "number": asn.get("Number"),
                    "description": asn.get("Description")[0] if asn.get("Description") else None
                }
                for asn in ip_whois.get("Asn", [])
            ],
            "net": {
                "range_start": ip_whois["Net"].get("RangeStart"),
                "range_end": ip_whois["Net"].get("RangeEnd"),
                "created": ip_whois["Net"].get("Created"),
                "changed": ip_whois["Net"].get("Changed"),
                "name": ip_whois["Net"].get("Name")
            }
        }

        kaspersky_ip_info_json = json.dumps(kaspersky_ip_info)

        session = Session()
        url_row = session.query(IOC).filter_by(ioc=user_ip).first()

        if url_row:
            url_row.kaspersky = kaspersky_ip_info_json
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
def kaspersky_file(user_hash):
    url = f"https://opentip.kaspersky.com/api/v1/search/hash?request={user_hash}"
    headers = { 
        "x-api-key": KASPERSKY_API
    }
    response = requests.request("GET", url, headers=headers)

    if response.status_code == 200:
        data = response.json()

        file_general_info = data.get("FileGeneralInfo", {})
        detections_info = data.get("DetectionsInfo", [])

        kaspersky_info = {
            "md5": file_general_info.get("Md5"),
            "sha1": file_general_info.get("Sha1"),
            "sha256": file_general_info.get("Sha256"),
            "file_status": file_general_info.get("FileStatus"),
            "first_seen": file_general_info.get("FirstSeen"),
            "last_seen": file_general_info.get("LastSeen"),
            "size": file_general_info.get("Size"),
            "file_type": file_general_info.get("Type"),
            "hits_count": file_general_info.get("HitsCount"),
            "detections": [
                {
                    "last_detect_date": detection.get("LastDetectDate"),
                    "description_url": detection.get("DescriptionUrl"),
                    "zone": detection.get("Zone"),
                    "detection_name": detection.get("DetectionName")
                }
                for detection in detections_info
            ]
        }

        kaspersky_info_json = json.dumps(kaspersky_info)

        session = Session()
        url_row = session.query(IOC).filter_by(ioc=user_hash).first()

        if url_row:
            url_row.kaspersky = kaspersky_info_json
            session.commit()
        session.close()

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
