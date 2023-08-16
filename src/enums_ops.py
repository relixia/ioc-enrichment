from enum import Enum, auto

from enums import InputType
from tasks import (abstract_email, abuseipdb, cloudflare_email, cloudflare_ip,
                   criminalip_domain, criminalip_ip, greynoise, hunterio,
                   hybridana_file, ipinfo, iplocation, ipqualityscore,
                   ipqualityscore_email, kaspersky_domain, kaspersky_file,
                   kaspersky_ip, kaspersky_url, openphish, opswat,
                   opswat_file_reputation, phishtank, shodan, urlhaus,
                   urlscanio, usom, virustotal_domain, virustotal_file,
                   virustotal_ip, virustotal_url)

input_task_mapping = {
    InputType.URL: [
        virustotal_url,
        kaspersky_url,
        urlscanio,
        cloudflare_email,
        urlhaus,
        phishtank,
        openphish,
        ipqualityscore,
    ],
    InputType.DOMAIN: [
        virustotal_domain,
        kaspersky_domain,
        criminalip_domain,
        cloudflare_email,
        usom,
        ipqualityscore,
    ],
    InputType.FILE_HASH: [
        virustotal_file,
        opswat,
        opswat_file_reputation,
        kaspersky_file,
        hybridana_file,
        cloudflare_email,
    ],
    InputType.IP_ADDRESS: [
        virustotal_ip,
        ipinfo,
        abuseipdb,
        greynoise,
        kaspersky_ip,
        criminalip_ip,
        cloudflare_ip,
        iplocation,
        shodan,
    ],
    InputType.EMAIL_ADDRESS: [
        ipqualityscore_email,
        abstract_email,
        hunterio,
        cloudflare_email,
    ],
}
