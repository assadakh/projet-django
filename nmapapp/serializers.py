from rest_framework import serializers
from .models import ScanNmap, ScanWhatweb, ScanZap


# Serializer pour Nmap 
class NmapScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanNmap
        fields = ['ip', 'port', 'state', 'service']


# Serializer pour WhatWeb
class WhatWebResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanWhatweb
        fields = ['url', 'result']


# Serializer pour ZAP  
class ZAPResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanZap
        fields = ['url', 'alert', 'risk', 'confidence', 'description', 'solution', 'reference']


