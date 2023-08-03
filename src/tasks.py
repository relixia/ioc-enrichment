from celery_base import app

# 
# 
'''
Kendi phishing servisim --> USOM, PhishTank, PhishStats, OpenPhish
VirusTotal: Dosya tarama, URL analizi, IP ve alan adı istihbaratı sağlayan bir hizmet.
Google reklamlar: https://adstransparency.google.com/?region=anywhere
Shodan: İnternet üzerindeki cihazlar için açık port ve servis bilgisi sağlayan bir hizmet.
AbuseIPDB: Zararlı IP adresleri hakkında bilgi sunan bir hizmet.
IPinfo: IP adresleri için coğrafi konum ve whois bilgileri sağlayan bir hizmet.
GreyNoise: İnternet gürültüsü ve zararlı IP adresleri arasındaki farkı belirleyen bir hizmet.
AlienVault OTX: Ağ trafiğini izleyen ve zararlı davranışları algılayan açık tehdit istihbaratı platformu.
URLhaus: Zararlı URL'leri içeren bir veritabanı.
'''

@app.task
def say_hello(name: str):
    return f"Hello {name}"