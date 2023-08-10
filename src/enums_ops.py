from enum import Enum, auto
from enums import InputType
from tasks import (
    virustotal_url, virustotal_file, virustotal_ip, virustotal_domain, ipinfo, abuseipdb, greynoise, opswat, opswat_file_reputation,
    kaspersky_file, kaspersky_ip, kaspersky_domain, kaspersky_url, hybridana_file, urlscanio, criminalip_ip, criminalip_domain,
    cloudflare_email, cloudflare_ip, iplocation, urlhaus, phishtank, usom, openphish, shodan, ipqualityscore, ipqualityscore_email,
    abstract_email, hunterio
)


input_task_mapping = {
    
    InputType.URL: [virustotal_url, kaspersky_url, urlscanio, cloudflare_email, urlhaus, phishtank, openphish, ipqualityscore],
    InputType.DOMAIN: [virustotal_domain, kaspersky_domain, criminalip_domain, cloudflare_email, usom, ipqualityscore],
    InputType.FILE_HASH: [virustotal_file, opswat, opswat_file_reputation, kaspersky_file, hybridana_file, cloudflare_email],
    InputType.IP_ADDRESS: [virustotal_ip, ipinfo, abuseipdb, greynoise, kaspersky_ip, criminalip_ip, cloudflare_ip, iplocation, shodan],
    InputType.EMAIL_ADDRESS: [ipqualityscore_email, abstract_email, hunterio, cloudflare_email]
}
