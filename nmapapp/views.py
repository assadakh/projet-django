from rest_framework.views import APIView
from django.shortcuts import render, redirect
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import status
from .models import ScanNmap, ScanWhatweb, ScanZap
from .serializers import NmapScanSerializer, WhatWebResultSerializer, ZAPResultSerializer
from .parsers import parse_nmap_output, parse_whatweb_output, parse_json_output

from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, authenticate
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
import subprocess
import time
import ipaddress
import requests
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken


def register_view(request):
    return render(request, "register.html")

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        if not username or not password:
            return render(request, "login.html", {'error': 'Veuillez remplir tous les champs'})
        
        # Authentifier l'utilisateur pour la session Django
        user = authenticate(request, username=username, password=password)
        if user is not None:
            # Connecter l'utilisateur dans la session
            login(request, user)
            # Générer un token JWT
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)
            # Passer les tokens au template pour les stocker dans localStorage
            next_url = request.GET.get('next', '/dashboard/')
            return render(request, "login.html", {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'redirect_to': next_url
            })
        else:
            return render(request, "login.html", {'error': 'Nom d\'utilisateur ou mot de passe incorrect'})
    
    return render(request, "login.html")

@login_required(login_url='/login')
def dashboard(request):
    return render(request, "dashboard.html")




### Enregistrement d'utilisateur
class RegisterAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response({"error": "Le nom d'utilisateur et le mot de passe sont obligatoires."}, status=400)

        if User.objects.filter(username=username).exists():
            return Response({"error": "Nom d'utilisateur déjà utilisé."}, status=400)

        User.objects.create_user(username=username, password=password)
        return Response({"message": "Utilisateur créé avec succès."}, status=201)



### NMAPVIEW
class NmapScanAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ip = request.GET.get("ip")  

        if not ip:
            return Response({
                "error": "Aucune IP fournie.",
                "scans": [],
                "url": ""
            })
        
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return Response({
                "error": "Adresse IP invalide. Veuillez entrer une IP correcte (ex : 192.168.1.1).",
                "scans": [],
                "ip": ip
            })
        
        scan_exist = ScanNmap.objects.filter(ip=ip)
        if scan_exist.exists():
            serializer = NmapScanSerializer(scan_exist, many=True)
            return Response({"ip": ip, "scans": serializer.data})

        ScanNmap.objects.filter(ip=ip).delete()

        commande = subprocess.run(["nmap", ip], capture_output=True, text=True)

        if commande.returncode != 0:
            return Response({
                "error": "Le scan Nmap a échoué. Vérifiez que Nmap est installé et que l’IP est accessible.",
                "scans": [],
                "ip": ip
            })

        brut_output = [line for line in commande.stdout.splitlines() if line.strip()]
        resultat = parse_nmap_output(brut_output)

        if not resultat:
            return Response({
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
        serializer = NmapScanSerializer(scans, many=True)
        return Response({
            "ip": ip,
            "scans": serializer.data
        })




### WHATWEBVIEW
class WhatWebScanAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        url = request.GET.get("url")

        if not url:
            return Response({
                "error": "Aucune URL fournie.",
                "scans": [],
                "url": ""
            })
        
        # ✅ Test la validité de l'URL 
        validate = URLValidator()
        try:
            validate(url)
        except ValidationError:
            return Response({
                "error": "Format d'URL invalide.",
                "scans": [],
                "url": url
            })
        
        # ✅ Vérification que l'URL est accessible via HTTP
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
        except requests.RequestException:
            return Response({
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
            return Response({
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

        return Response({
            "url": url,
            "scans": result_list
        })




### ZAPVIEW
class ZapScanAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        apikey = "80mb2scd3nqge4vnbu7midf1q1"
        url = request.GET.get("url")

        if not url:
            return Response({
                "error": "Aucune URL fournie.",
                "scans": [],
                "url": ""
            })
        
        # ✅ Test la validité de l'URL 
        validate = URLValidator()
        try:
            validate(url)
        except ValidationError:
            return Response({
                "error": "Format d'URL invalide.",
                "scans": [],
                "url": url
            })
        
        # ✅ Vérification que l'URL est accessible via HTTP
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
        except requests.RequestException:
            return Response({
                "error": "L'URL n'est pas accessible (erreur réseau ou code HTTP non valide).",
                "scans": [],
                "url": url
            })
        
        # Vérifie si un scan existe déjà en base pour cette URL   
        scan_exist = ScanZap.objects.filter(url=url)
        if scan_exist.exists():
            # Si oui, on récupère directement les données existantes
            serializer = ZAPResultSerializer(scan_exist, many=True)
            return Response({"url": url, "scans": serializer.data})

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
        return Response({
            "url": url,
            "scans": serializer.data
        })
