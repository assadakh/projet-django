from django.shortcuts import render
import subprocess

# Create your views here.
def nmap_scan(request):
    ip = "192.168.1.1"

    commande = subprocess.run(["nmap", ip], capture_output=True, text=True)
    resultat = commande.stdout 

    return render(request, "nmapapp/nmap_scan.html", {"ip": ip, "resultat": resultat})

def whatweb_scan(request):
    url = "http://testphp.vulnweb.com"

    commande = subprocess.run(["wsl", "-d", "Ubuntu", "whatweb", url], capture_output=True, text=True)
    resultat = commande.stdout 

    return render(request, "nmapapp/whatweb_scan.html", {"url": url, "resultat": resultat})

import subprocess
import time
from django.shortcuts import render

def zap_scan(request):
    url = "http://testphp.vulnweb.com"
    apikey = "80mb2scd3nqge4vnbu7midf1q1"
    
    # Lancement d'un scan Spider
    spider_url = f"http://127.0.0.1:8090/JSON/spider/action/scan/?apikey={apikey}&url={url}"
    ps_spider = f'Invoke-WebRequest -Uri "{spider_url}" -UseBasicParsing'
    subprocess.run(["powershell", "-Command", ps_spider], capture_output=True, text=True)

    # On attend quelques secondes que le Spider découvre les pages
    time.sleep(5)

    # Lancer un scan actif (ascan)
    ascan_url = f"http://127.0.0.1:8090/JSON/ascan/action/scan/?apikey={apikey}&url={url}"
    ps_ascan = f'Invoke-WebRequest -Uri "{ascan_url}" -UseBasicParsing'
    resultat = subprocess.run(["powershell", "-Command", ps_ascan], capture_output=True, text=True)

    return render(request, "nmapapp/zap_scan.html", {"url": url,"resultat": resultat.stdout})
