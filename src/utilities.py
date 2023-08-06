import re, hashlib, uuid, json, csv, gzip, requests
from models import IOC, Session, engine
from sqlalchemy.orm import sessionmaker

Session = sessionmaker(bind=engine)

def check_input_type(input_text):
    # Check if it's an IP address
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', input_text):
        return "IP Address"
    # Check if it's a URL
    elif input_text.startswith(("http://", "https://")):
        return "URL"
    # Check if it's a domain
    elif re.match(r'^(?:(?:https?://)?(?:www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|localhost)(?:/|$)', input_text):
        return "Domain"
    # Check if it's a file hash (MD5, SHA-1, or SHA-256)
    elif re.match(r'^[a-fA-F0-9]{32}$', input_text) or re.match(r'^[a-fA-F0-9]{40}$', input_text) or re.match(r'^[a-fA-F0-9]{64}$', input_text):
        return "File Hash"
    # Check if it's an email address
    elif re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', input_text):
        return "Email Address"
    else:
        return "Invalid Input"
        
def calculate_file_hash(file_content):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_content)
    return sha256_hash.hexdigest()

def ioc_save_db(ioc, ioc_type):
    url_data = IOC(id=str(uuid.uuid4()), ioc=ioc, ioc_type=ioc_type)

    session = Session()
    session.add(url_data)
    session.commit()
    session.close()

def virustotal_save(response, ioc_name):
    data = response.json()
    virustotal_data = data["data"]["attributes"]["last_analysis_results"]
    virustotal_json = json.dumps(virustotal_data)

    session = Session()
    url_row = session.query(IOC).filter_by(ioc=ioc_name).first()

    if url_row:
        url_row.virustotal = virustotal_json
        session.commit()
    session.close()

def check_phishtank(url_to_check):
    phishtank_url = "http://data.phishtank.com/data/online-valid.csv.gz"
    response = requests.get(phishtank_url)
    
    if response.status_code != 200:
        print("Failed to download the PhishTank database.")
    else:
        csv_content = gzip.decompress(response.content).decode("utf-8")
        csv_reader = csv.DictReader(csv_content.splitlines())
        phishtank_data = list(csv_reader)

        for entry in phishtank_data:
            if "url" in entry and url_to_check in entry["url"]:
                return True
        
    return False

def check_usom(url_to_check):
    usom_url = "https://www.usom.gov.tr/url-list.txt"
    response = requests.get(usom_url)
    
    if response.status_code != 200:
        print("Failed to download the USOM malicious URL database.")
        return False

    usom_data = response.text.splitlines()
    if url_to_check in usom_data:
        return True
        
    return False

def check_openphish(url_to_check):
    openphish_url = "https://openphish.com/feed.txt"
    response = requests.get(openphish_url)
    
    if response.status_code != 200:
        print("Failed to download the OpenPhish malicious URL database.")
        return False

    openphish_data = response.text.splitlines()
    if url_to_check in openphish_data:
        return True
        
    return False
