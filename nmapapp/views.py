from rest_framework.views import APIView
from django.shortcuts import render
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
import subprocess
import time
import ipaddress
import requests
from .models import ScanNmap, ScanWhatweb, ScanZap
from .serializers import NmapScanSerializer, WhatWebResultSerializer, ZAPResultSerializer
from .parsers import parse_nmap_output, parse_whatweb_output, parse_json_output


class NmapScanAPIView(APIView):
    def get(self, request):
        ip = request.GET.get("ip")  
        
        # ✅ Validation de l'adresse IP
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return render(request, "nmap_scan.html", {
                "error": "Adresse IP invalide. Veuillez entrer une IP correcte (ex : 192.168.1.1).",
                "scans": [],
                "ip": ip
            })
        
        scans_existants = ScanNmap.objects.filter(ip=ip)
        if scans_existants.exists():
            serializer = NmapScanSerializer(scans_existants, many=True)
            return render(request, "nmap_scan.html", {"ip": ip, "scans": serializer.data})

        commande = subprocess.run(["nmap", ip], capture_output=True, text=True)
        brut_output = [line for line in commande.stdout.splitlines() if line.strip()]
        resultat = parse_nmap_output(brut_output)

        ScanNmap.objects.filter(ip=ip).delete()

        scan_objects = [
            ScanNmap(
                ip=ip,
                port=entry.get("port"),
                state=entry.get("state"),
                service=entry.get("service")
            )
            for entry in resultat
        ]
        ScanNmap.objects.bulk_create(scan_objects)

        scans = ScanNmap.objects.filter(ip=ip)
        serializer = NmapScanSerializer(scans, many=True)
        return render(request, "nmap_scan.html", {"ip": ip, "scans": serializer.data})




class WhatWebScanAPIView(APIView):
    def get(self, request):
        url = request.GET.get("url")

        
        # ✅ Test la validité de l'URL 
        validate = URLValidator()
        try:
            validate(url)
        except ValidationError:
            return render(request, "zap_scan.html", {
                "error": "Format d'URL invalide.",
                "scans": [],
                "url": url
            })
        
        # ✅ Vérification que l'URL est accessible via HTTP
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
        except requests.RequestException:
            return render(request, "zap_scan.html", {
                "error": "L'URL n'est pas accessible (erreur réseau ou code HTTP non valide).",
                "scans": [],
                "url": url
            })

        # Vérifie si un scan existe déjà en base pour cette URL
        scan_exist = ScanWhatweb.objects.filter(url=url).first()
        if scan_exist:
            # Si oui, on récupère directement les données existantes
            serializer = WhatWebResultSerializer(scan_exist)
            result_list = serializer.data["result"].split(", ")
            return render(request, "whatweb_scan.html", {
                "url": url,
                "result_list": result_list
            })

        # Sinon lance le scan et enregistre
        commande = subprocess.run(
            ["wsl", "-d", "Ubuntu", "whatweb", "--color=never", url],
            capture_output=True,
            text=True
        )
        brut_output = [line for line in commande.stdout.splitlines() if line.strip()]
        resultat = parse_whatweb_output(brut_output)

        ScanWhatweb.objects.filter(url=url).delete()
        ScanWhatweb.objects.create(url=url, result=", ".join(resultat))

        scan_whatweb = ScanWhatweb.objects.get(url=url)
        serializer = WhatWebResultSerializer(scan_whatweb)
        result_list = serializer.data["result"].split(", ")

        return render(request, "whatweb_scan.html", {
            "url": url,
            "result_list": result_list
        })


class ZapScanAPIView(APIView):
    def get(self, request):
        apikey = "80mb2scd3nqge4vnbu7midf1q1"
        url = request.GET.get("url")


        # ✅ Test la validité de l'URL 
        validate = URLValidator()
        try:
            validate(url)
        except ValidationError:
            return render(request, "zap_scan.html", {
                "error": "Format d'URL invalide.",
                "scans": [],
                "url": url
            })
        
        # ✅ Vérification que l'URL est accessible via HTTP
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
        except requests.RequestException:
            return render(request, "zap_scan.html", {
                "error": "L'URL n'est pas accessible (erreur réseau ou code HTTP non valide).",
                "scans": [],
                "url": url
            })
        
        # Vérifie si un scan existe déjà en base pour cette URL   
        scans_existants = ScanZap.objects.filter(url=url)
        if scans_existants.exists():
            # Si oui, on récupère directement les données existantes
            serializer = ZAPResultSerializer(scans_existants, many=True)
            return render(request, "zap_scan.html", {"url": url, "scans": serializer.data})

        subprocess.run(
            ["powershell", "-Command",
             f'Invoke-WebRequest -Uri "http://127.0.0.1:8090/JSON/spider/action/scan/?apikey={apikey}&url={url}" -UseBasicParsing'],
            capture_output=True, text=True
        )
        time.sleep(5)

        subprocess.run(
            ["powershell", "-Command",
             f'Invoke-WebRequest -Uri "http://127.0.0.1:8090/JSON/ascan/action/scan/?apikey={apikey}&url={url}" -UseBasicParsing'],
            capture_output=True, text=True
        )
        time.sleep(15)

        result = subprocess.run(
            ["powershell", "-Command",
             f'(Invoke-WebRequest -Uri "http://127.0.0.1:8090/JSON/core/view/alerts/?baseurl={url}&apikey={apikey}").Content'],
            capture_output=True, text=True
        )

        alerts = parse_json_output(result.stdout)

        ScanZap.objects.filter(url=url).delete()
        scanzap_objects = [
            ScanZap(
                url=url,
                alert=alert.get("alert"),
                name=alert.get("name", ""),
                risk=alert.get("risk", ""),
                confidence=alert.get("confidence", ""),
                description=alert.get("description", ""),
                solution=alert.get("solution", ""),
                reference=alert.get("reference", "")
            ) for alert in alerts
        ]
        ScanZap.objects.bulk_create(scanzap_objects)

        scans = ScanZap.objects.filter(url=url)
        serializer = ZAPResultSerializer(scans, many=True)
        return render(request, "zap_scan.html", {"url": url, "scans": serializer.data})
















# class nmapscan(APIView):
#     def get(self, request):
#         ip = "192.168.1.1"

#         # Lance la commande Nmap sur l'IP
#         commande = subprocess.run(["nmap", ip], capture_output=True, text=True)

#         # Nettoie la sortie : enlève les lignes vides
#         brut_output = [line for line in commande.stdout.splitlines() if line.strip()]

#         # Analyse la sortie brute avec le parseur pour récupérer les ports ouverts et services
#         resultat = parse_nmap_output(brut_output)

#         # Prépare les données structurées à renvoyer
#         data = {"ip": ip, "result": resultat}

#         # Sérialise et valide les données
#         serializer = NmapScanSerializer(data=data)
#         serializer.is_valid(raise_exception=True)
#         return Response(serializer.data)



# class whatwebscan(APIView):
#     def get(self, request):
#         url = "http://testphp.vulnweb.com"

#         # Lance la commande WhatWeb via WSL sur l'URL cible
#         commande = subprocess.run(["wsl", "-d", "Ubuntu", "whatweb", "--color=never", url], capture_output=True, text=True)

#         # Nettoie la sortie brute pour enlever les lignes vides
#         brut_output = [line for line in commande.stdout.splitlines() if line.strip()]

#         # Analyse la sortie brute pour extraire la liste des plugins/technologies détectées
#         resultat = parse_whatweb_output(brut_output)

#         # Prépare les données à envoyer
#         data = {"url": url, "result": resultat}

#         # Sérialise et valide les données
#         serializer = WhatWebResultSerializer(data=data)
#         serializer.is_valid(raise_exception=True)
#         return Response(serializer.data)



# class zapscan(APIView):
#     def get(self, request):
#         url = "http://testphp.vulnweb.com"
#         apikey = "80mb2scd3nqge4vnbu7midf1q1"

#         # Lance le spider ZAP (scan d'exploration)
#         spider_url = f"http://127.0.0.1:8090/JSON/spider/action/scan/?apikey={apikey}&url={url}"
#         subprocess.run(["powershell", "-Command", f'Invoke-WebRequest -Uri "{spider_url}" -UseBasicParsing'],
#                        capture_output=True, text=True)

#         # Attend que le spider termine 
#         time.sleep(5)

#         # Lance le scan actif ZAP
#         ascan_url = f"http://127.0.0.1:8090/JSON/ascan/action/scan/?apikey={apikey}&url={url}"
#         subprocess.run(["powershell", "-Command", f'Invoke-WebRequest -Uri "{ascan_url}" -UseBasicParsing'],
#                        capture_output=True, text=True)

#         # Attend que le scan actif termine 
#         time.sleep(15)

#         # Récupère les alertes au format JSON via l’API ZAP
#         alerts_url = f"http://127.0.0.1:8090/JSON/core/view/alerts/?baseurl={url}&apikey={apikey}"

#         result = subprocess.run(["powershell", "-Command", f'(Invoke-WebRequest -Uri "{alerts_url}" -UseBasicParsing).Content'], capture_output=True, text=True)

#         # Parse la sortie JSON
#         alerts = parse_json_output(result.stdout)

#         # Prépare la réponse
#         data = {"url": url, "result": alerts}

#         # Sérialise et retourne la réponse
#         serializer = ZAPResultSerializer(data=data)
#         serializer.is_valid(raise_exception=True)
#         return Response(serializer.data)
