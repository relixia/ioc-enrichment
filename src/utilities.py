import re
import hashlib
from models import IOC, Session, engine
from sqlalchemy.orm import sessionmaker
import uuid
import json

Session = sessionmaker(bind=engine)

def check_input_type(input_text):
    # Check if it's a URL or domain
    if re.match(r'^(?:(?:https?://)?(?:www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|localhost)(?:/|$)|^(?:https?://)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/|$)', input_text):
        return "URL" if input_text.startswith(("http://", "https://")) else "Domain"
    # Check if it's an IP address
    elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', input_text):
        return "IP Address"
    # Check if it's a file hash (MD5, SHA-1, or SHA-256)
    elif re.match(r'^[a-fA-F0-9]{32}$', input_text) or re.match(r'^[a-fA-F0-9]{40}$', input_text) or re.match(r'^[a-fA-F0-9]{64}$', input_text):
        return "File Hash"
    else:
        return "Invalid Input"
        
def calculate_file_hash(file_content):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_content)
    return sha256_hash.hexdigest()

def ioc_save_db(ioc, ioc_type):
    # Create a new URL object with the given data
    url_data = IOC(id=str(uuid.uuid4()), ioc=ioc, ioc_type=ioc_type)

    # Add the URL object to the database
    session = Session()
    session.add(url_data)
    session.commit()
    session.close()

def virustotal_save(response, ioc_name):
    data = response.json()
    virustotal_data = data["data"]["attributes"]["last_analysis_results"]
    # Convert the 'virustotal_data' dictionary to a JSON string
    virustotal_json = json.dumps(virustotal_data)

    session = Session()
    url_row = session.query(IOC).filter_by(ioc=ioc_name).first()

    if url_row:
        url_row.virustotal = virustotal_json
        session.commit()
    session.close()
