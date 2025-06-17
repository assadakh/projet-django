from rest_framework.views import APIView
from django.shortcuts import render
from .models import ScanNmap, ScanWhatweb, ScanZap
from .serializers import NmapScanSerializer, WhatWebResultSerializer, ZAPResultSerializer
from .parsers import parse_nmap_output, parse_whatweb_output, parse_json_output

from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
import subprocess
import time
import ipaddress
import requests





### NMAPVIEW
class NmapScanAPIView(APIView):
    def get(self, request):
        ip = request.GET.get("ip")  

        if not ip:
            return render(request, "nmap_scan.html", {
                "error": "Aucune IP fournie.",
                "scans": [],
                "url": ""
            })
        
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return render(request, "nmap_scan.html", {
                "error": "Adresse IP invalide. Veuillez entrer une IP correcte (ex : 192.168.1.1).",
                "scans": [],
                "ip": ip
            })
        
        scan_exist = ScanNmap.objects.filter(ip=ip)
        if scan_exist.exists():
            serializer = NmapScanSerializer(scan_exist, many=True)
            return render(request, "nmap_scan.html", {"ip": ip, "scans": serializer.data})

        ScanNmap.objects.filter(ip=ip).delete()

        commande = subprocess.run(["nmap", ip], capture_output=True, text=True)

        if commande.returncode != 0:
            return render(request, "nmap_scan.html", {
                "error": "Le scan Nmap a échoué. Vérifiez que Nmap est installé et que l’IP est accessible.",
                "scans": [],
                "ip": ip
            })

        brut_output = [line for line in commande.stdout.splitlines() if line.strip()]
        resultat = parse_nmap_output(brut_output)

        if not resultat:
            return render(request, "nmap_scan.html", {
                "error": "Aucun port détecté ou tous les ports sont filtrés.",
                "scans": [],
                "ip": ip
            })

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
        return render(request, "nmap_scan.html", {"ip": ip, "scans": scans})




### WHATWEBVIEW
class WhatWebScanAPIView(APIView):
    def get(self, request):
        url = request.GET.get("url")

        if not url:
            return render(request, "whatweb_scan.html", {
                "error": "Aucune URL fournie.",
                "scans": [],
                "url": ""
            })
        
        # ✅ Test la validité de l'URL 
        validate = URLValidator()
        try:
            validate(url)
        except ValidationError:
            return render(request, "whatweb_scan.html", {
                "error": "Format d'URL invalide.",
                "scans": [],
                "url": url
            })
        
        # ✅ Vérification que l'URL est accessible via HTTP
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
        except requests.RequestException:
            return render(request, "whatweb_scan.html", {
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
                "scans": result_list
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
            "scans": result_list
        })




### ZAPVIEW
class ZapScanAPIView(APIView):
    def get(self, request):
        apikey = "80mb2scd3nqge4vnbu7midf1q1"
        url = request.GET.get("url")

        if not url:
            return render(request, "zap_scan.html", {
                "error": "Aucune URL fournie.",
                "scans": [],
                "url": ""
            })
        
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
        scan_exist = ScanZap.objects.filter(url=url)
        if scan_exist.exists():
            # Si oui, on récupère directement les données existantes
            serializer = ZAPResultSerializer(scan_exist, many=True)
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