from django.views import View
from django.shortcuts import render
import subprocess
import time

# Create your views here.

# Création de 3 classes pour pouvoir afficher le résultat des commandes PowerShell 
class nmap_scan(View):
    def get(self, request):
        # Initialisation de l'IP
        ip = "192.168.1.1"
        # Commande stockée dans une variable et effectuée
        commande = subprocess.run(["nmap", ip], capture_output=True, text=True)
        # Résultat de la commande stocké
        resultat = commande.stdout 

        # Retour de l'affichage
        return render(request, "nmapapp/nmap_scan.html", {"ip": ip, "resultat": resultat})
    

class whatweb_scan(View):
    def get(self, request):
        # Initialisation de l'URL
        url = "http://testphp.vulnweb.com"
        # Commande stockée dans une variable et effectuée
        commande = subprocess.run(["wsl", "-d", "Ubuntu", "whatweb", url], capture_output=True, text=True)
        # Résultat de la commande stocké
        resultat = commande.stdout 

        # Retour de l'affichage
        return render(request, "nmapapp/whatweb_scan.html", {"url": url, "resultat": resultat})
    

class zap_scan(View):
    def get(self, request):
        # Initialisation de l'URL et de la clé alphanumérique
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

        # Retour de l'affichage
        return render(request, "nmapapp/zap_scan.html", {"url": url,"resultat": resultat.stdout})
