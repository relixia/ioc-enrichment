import re
import hashlib

def check_input_type(input_text):
    # Check if it's a URL or domain
    if re.match(r'^(https?://)?(?:www\.)?([a-zA-Z0-9.-]+)\.[a-zA-Z]{2,}$', input_text):
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
