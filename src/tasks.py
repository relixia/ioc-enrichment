from celery_base import app
from models import Base, Session, IOC
from utilities import virustotal_save, check_phishtank, check_usom, check_openphish
import requests, os, json, csv
from dotenv import load_dotenv
from urllib.parse import quote

envs_path = os.path.join(os.path.dirname(__file__), "../envs/.env")
load_dotenv(dotenv_path=envs_path)

VIRUSTOTAL_API = os.getenv("VIRUSTOTAL_API")
IPINFO_API = os.getenv("IPINFO_API")
ABUSEIPDB_API = os.getenv("ABUSEIPDB_API")
GREYNOISE_API = os.getenv("GREYNOISE_API")
OPSWAT_API = os.getenv("OPSWAT_API")
KASPERSKY_API = os.getenv("KASPERSKY_API")
HYBRIDANA_API = os.getenv("HYBRIDANA_API")
URLSCANIO_API = os.getenv("URLSCANIO_API")
CRIMINALIP_API = os.getenv("CRIMINALIP_API")
CLOUDFLARE_API = os.getenv("CLOUDFLARE_API")
CLOUDFLARE_EMAIL = os.getenv("CLOUDFLARE_EMAIL")
SHODAN_API = os.getenv("SHODAN_API")
IPQUALITYSCORE_API = os.getenv("IPQUALITYSCORE_API")
# iplocation is also used
# urlhaus is also used
# phishtank is also used
# usom is also used
# openphish is also used

#----------------------------------------------------FOR URL IOCS-------------------------------------------------------------
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

@app.task
def urlscanio(user_url):
    headers = {
        'API-Key': URLSCANIO_API,
        'Content-Type': 'application/json'
    }
    data = {
        "url": user_url, 
        "visibility": "public"
    }
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))
    if response.status_code == 200:
        scan_data = response.json()
        session = Session()
        url_row = session.query(IOC).filter_by(ioc=user_url).first()

        if url_row:
            url_row.urlscanio = json.dumps(scan_data)
            session.commit()
        session.close()

@app.task
def urlhaus(user_url):
    url = f"https://urlhaus-api.abuse.ch/v1/url/"
    data = {
        "url": user_url
    }
    response = requests.post(url, data=data)    
    if response.status_code == 200:
        scan_data = response.json()
        session = Session()
        url_row = session.query(IOC).filter_by(ioc=user_url).first()
        if url_row:
            url_row.urlhaus = json.dumps(scan_data)
            session.commit()
        session.close()
    
@app.task
def phishtank(user_url):
    session = Session()
    url_row = session.query(IOC).filter_by(ioc=user_url).first()
    if url_row:
        if check_phishtank(user_url):
            url_row.phishtank = "The url provided is in the PhishTank database and it is SUSPICIOUS / MALICIOUS. Be careful!"
            session.commit()
        else:
            url_row.phishtank = "The url provided is NOT in the PhishTank database."
            session.commit()
    session.close()
    
@app.task
def openphish(user_url):
    session = Session()
    url_row = session.query(IOC).filter_by(ioc=user_url).first()
    if url_row:
        if check_openphish(user_url):
            url_row.openphish = "The url provided is in the OpenPhish malicious URL database. BE CAREFUL!"
            session.commit()
        else:
            url_row.openphish = "The url provided is NOT in the OpenPhish malicious URL database."
            session.commit()
    session.close()

@app.task
def ipqualityscore(user_url): #BOTH FOR URL AND DOMAIN
    user_url_in_db = user_url
    if user_url.startswith("http://"):
        user_url = user_url[len("http://"):]
    elif user_url.startswith("https://"):
        user_url = user_url[len("https://"):]
    encoded_url = quote(user_url)
    url = f"https://www.ipqualityscore.com/api/json/url/{IPQUALITYSCORE_API}/{encoded_url}"
    response = requests.post(url)
    if response.status_code == 200:
        scan_data = response.json()
        session = Session()
        url_row = session.query(IOC).filter_by(ioc=user_url_in_db).first()
        if url_row:
            url_row.ipqualityscore = json.dumps(scan_data)
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

@app.task
def criminalip_domain(user_domain):
    url = "https://api.criminalip.io/v1/domain/reports?query=example.com&offset=0"
    payload={}
    headers = { "x-api-key": CRIMINALIP_API }
    response = requests.request("GET", url, headers=headers, data=payload)
    if response.status_code == 200:
        data = response.json()
        criminalip_info_json = json.dumps(data)
        session = Session()
        url_row = session.query(IOC).filter_by(ioc=user_domain).first()

        if url_row:
            url_row.criminalip = criminalip_info_json
            session.commit()
        session.close()

@app.task
def usom(user_url):
    session = Session()
    url_row = session.query(IOC).filter_by(ioc=user_url).first()

    if check_usom(user_url):
        if url_row:
            url_row.usom = "The Domain provided is in the USOM malicious domain database. BE CAREFUL!"
            session.commit()
    else:
        if url_row:
            url_row.usom = "The Domain provided is NOT in the USOM malicious domain database."
            session.commit()

    session.close()


#----------------------------------------------------FOR IP ADDRESS IOCS-------------------------------------------------------------
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

@app.task
def criminalip_ip(user_ip):
    url = f"https://api.criminalip.io/v1/ip/data?ip={user_ip}&full=true"
    payload={}
    headers = {"x-api-key": CRIMINALIP_API}

    response = requests.request("GET", url, headers=headers, data=payload)
    if response.status_code == 200:
        data = response.json()
        criminalip_info_json = json.dumps(data)
        session = Session()
        url_row = session.query(IOC).filter_by(ioc=user_ip).first()

        if url_row:
            url_row.criminalip = criminalip_info_json
            session.commit()
        session.close()

@app.task
def cloudflare_ip(user_ip):
    url = "https://api.cloudflare.com/client/v4/radar/entities/asns/ip"

    headers = {
        "Content-Type": "application/json",
        "X-Auth-Email": CLOUDFLARE_EMAIL,
        "X-Auth-Key": CLOUDFLARE_API
    }
    params = {
        "format": "json",
        "ip": user_ip
    }
    response = requests.request("GET", url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        cloudflare_info_json = json.dumps(data)
        session = Session()
        url_row = session.query(IOC).filter_by(ioc=user_ip).first()

        if url_row:
            url_row.cloudflare = cloudflare_info_json
            session.commit()
        session.close()

@app.task
def iplocation(user_ip):
    url = f"https://api.iplocation.net/?ip={user_ip}"
    response = requests.request("GET", url)
    if response.status_code == 200:
        data = response.json()
        iplocation_info_json = json.dumps(data)
        session = Session()
        url_row = session.query(IOC).filter_by(ioc=user_ip).first()

        if url_row:
            url_row.iplocation = iplocation_info_json
            session.commit()
        session.close()

@app.task
def shodan(user_ip):
    url = f"https://api.shodan.io/shodan/host/{user_ip}?key={SHODAN_API}"
    response = requests.request("GET", url)
    if response.status_code == 200:
        data = response.json()
        shodan_info_json = json.dumps(data)
        session = Session()
        url_row = session.query(IOC).filter_by(ioc=user_ip).first()
        if url_row:
            url_row.shodan = shodan_info_json
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
def hybridana_file(user_hash):
    url = f"https://www.hybrid-analysis.com/api/v2/overview/{user_hash}"
    headers = {
        "api-key": HYBRIDANA_API,
        "accept": "application/json",
        "user-agent": "Falcon Sandbox"
    }
    response = requests.request("GET", url, headers=headers)

    if response.status_code == 200:
        data = response.json()

        file_info = {
            "md5": data.get("md5"),
            "sha1": data.get("sha1"),
            "sha256": data.get("sha256"),
            "last_file_name": data.get("last_file_name"),
            "other_file_name": data.get("other_file_name"),
            "threat_score": data.get("threat_score"),
            "verdict": data.get("verdict"),
            "url_analysis": data.get("url_analysis"),
            "size": data.get("size"),
            "type": data.get("type"),
            "type_short": data.get("type_short"),
            "analysis_start_time": data.get("analysis_start_time"),
            "last_multi_scan": data.get("last_multi_scan"),
            "tags": data.get("tags"),
            "architecture": data.get("architecture"),
            "vx_family": data.get("vx_family"),
            "multiscan_result": data.get("multiscan_result"),
            "scanners": data.get("scanners"),
            "scanners_v2": data.get("scanners_v2"),
            "reports": data.get("reports"),
            "whitelisted": data.get("whitelisted"),
            "children_in_queue": data.get("children_in_queue"),
            "children_in_progress": data.get("children_in_progress"),
        }

        file_info_json = json.dumps(file_info)

        session = Session()
        hash_row = session.query(IOC).filter_by(ioc=user_hash).first()

        if hash_row:
            hash_row.hybrid_analysis = file_info_json
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

#----------------------------------------------------FOR EMAIL-------------------------------------------------------------
@app.task
def cloudflare_email(input_text):
    url = "https://api.cloudflare.com/client/v4/radar/email/security/summary/malicious"

    headers = {
        "Content-Type": "application/json",
        "X-Auth-Email": CLOUDFLARE_EMAIL,
        "X-Auth-Key": CLOUDFLARE_API
    }
    params = {
        "format": "json",
        "dateRange": "7d"
    }

    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        cloudflare_info_json = json.dumps(data)
        session = Session()
        url_row = session.query(IOC).filter_by(ioc=input_text).first()

        if url_row:
            url_row.cloudflare_email = cloudflare_info_json
            session.commit()
        session.close()
