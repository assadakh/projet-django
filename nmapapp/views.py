from rest_framework.response import Response
from rest_framework.views import APIView
import subprocess
import time
import json
from .serializers import NmapScanSerializer, WhatWebResultSerializer, ZAPResultSerializer
from .parsers import parse_nmap_output, parse_whatweb_output, parse_json_output


class nmapscan(APIView):
    def get(self, request):
        ip = "192.168.1.1"

        # Lance la commande Nmap sur l'IP
        commande = subprocess.run(["nmap", ip], capture_output=True, text=True)

        # Nettoie la sortie : enlève les lignes vides
        brut_output = [line for line in commande.stdout.splitlines() if line.strip()]

        # Analyse la sortie brute avec le parseur pour récupérer les ports ouverts et services
        resultat = parse_nmap_output(brut_output)

        # Prépare les données structurées à renvoyer
        data = {"ip": ip, "result": resultat}

        # Sérialise et valide les données
        serializer = NmapScanSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)



class whatwebscan(APIView):
    def get(self, request):
        url = "http://testphp.vulnweb.com"

        # Lance la commande WhatWeb via WSL sur l'URL cible
        commande = subprocess.run(["wsl", "-d", "Ubuntu", "whatweb", url], capture_output=True, text=True)

        # Nettoie la sortie brute pour enlever les lignes vides
        brut_output = [line for line in commande.stdout.splitlines() if line.strip()]

        # Analyse la sortie brute pour extraire la liste des plugins/technologies détectées
        resultat = parse_whatweb_output(brut_output)

        # Prépare les données à envoyer
        data = {"url": url, "result": resultat}

        # Sérialise et valide les données
        serializer = WhatWebResultSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)



class zapscan(APIView):
    def get(self, request):
        url = "http://testphp.vulnweb.com"
        apikey = "80mb2scd3nqge4vnbu7midf1q1"

        # Lance le spider ZAP (scan d'exploration)
        spider_url = f"http://127.0.0.1:8090/JSON/spider/action/scan/?apikey={apikey}&url={url}"
        subprocess.run(["powershell", "-Command", f'Invoke-WebRequest -Uri "{spider_url}" -UseBasicParsing'],
                       capture_output=True, text=True)

        # Attend que le spider termine 
        time.sleep(5)

        # Lance le scan actif ZAP
        ascan_url = f"http://127.0.0.1:8090/JSON/ascan/action/scan/?apikey={apikey}&url={url}"
        subprocess.run(["powershell", "-Command", f'Invoke-WebRequest -Uri "{ascan_url}" -UseBasicParsing'],
                       capture_output=True, text=True)

        # Attend que le scan actif termine 
        time.sleep(15)

        # Récupère les alertes au format JSON via l’API ZAP
        alerts_url = f"http://127.0.0.1:8090/JSON/core/view/alerts/?baseurl={url}&apikey={apikey}"

        result = subprocess.run(["powershell", "-Command", f'(Invoke-WebRequest -Uri "{alerts_url}" -UseBasicParsing).Content'], capture_output=True, text=True)

        # Parse la sortie JSON
        alerts = parse_json_output(result.stdout)

        # Prépare la réponse
        data = {"url": url, "result": alerts}

        # Sérialise et retourne la réponse
        serializer = ZAPResultSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)
















# from django.views import View
# from django.shortcuts import render
# import subprocess
# import time
# from rest_framework.response import Response

# # Create your views here.

# # Création de 3 classes pour pouvoir afficher le résultat des commandes PowerShell 
# class nmap_scan(View):
#     def get(self, request):
#         # Initialisation de l'IP
#         ip = "192.168.1.1"
#         # Commande stockée dans une variable et effectuée
#         commande = subprocess.run(["nmap", ip], capture_output=True, text=True)
#         # Résultat de la commande stocké
#         resultat = commande.stdout 

#         # Retour de l'affichage
#         return render(request, "nmapapp/nmap_scan.html", {"ip": ip, "resultat": resultat})
    

# class whatweb_scan(View):
#     def get(self, request):
#         # Initialisation de l'URL
#         url = "http://testphp.vulnweb.com"
#         # Commande stockée dans une variable et effectuée
#         commande = subprocess.run(["wsl", "-d", "Ubuntu", "whatweb", url], capture_output=True, text=True)
#         # Résultat de la commande stocké
#         resultat = commande.stdout 

#         # Retour de l'affichage
#         return render(request, "nmapapp/whatweb_scan.html", {"url": url, "resultat": resultat})
    

# class zap_scan(View):
#     def get(self, request):
#         # Initialisation de l'URL et de la clé alphanumérique
#         url = "http://testphp.vulnweb.com"
#         apikey = "80mb2scd3nqge4vnbu7midf1q1"
        
#         # Lancement d'un scan Spider
#         spider_url = f"http://127.0.0.1:8090/JSON/spider/action/scan/?apikey={apikey}&url={url}"
#         ps_spider = f'Invoke-WebRequest -Uri "{spider_url}" -UseBasicParsing'
#         subprocess.run(["powershell", "-Command", ps_spider], capture_output=True, text=True)

#         # On attend quelques secondes que le Spider découvre les pages
#         time.sleep(5)

#         # Lancer un scan actif (ascan)
#         ascan_url = f"http://127.0.0.1:8090/JSON/ascan/action/scan/?apikey={apikey}&url={url}"
#         ps_ascan = f'Invoke-WebRequest -Uri "{ascan_url}" -UseBasicParsing'
#         resultat = subprocess.run(["powershell", "-Command", ps_ascan], capture_output=True, text=True)

#         # Retour de l'affichage
#         return render(request, "nmapapp/zap_scan.html", {"url": url,"resultat": resultat.stdout})