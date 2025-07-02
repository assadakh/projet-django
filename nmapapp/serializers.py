from rest_framework import serializers
from .models import ScanNmap, ScanWhatweb, ScanZap

class NmapScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanNmap
        fields = ['id', 'ip', 'port', 'state', 'service', 'date_scan']
        extra_kwargs = {
            'date_scan': {'format': '%Y-%m-%dT%H:%M:%S.%f%z'}  # Inclut microsecondes et fuseau
        }

class WhatWebResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanWhatweb
        fields = ['id', 'url', 'result', 'date_scan']
        extra_kwargs = {
            'date_scan': {'format': '%Y-%m-%dT%H:%M:%S.%f%z'}
        }

class ZAPResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanZap
        fields = ['id', 'url', 'alert', 'name', 'risk', 'confidence', 'description', 'solution', 'reference', 'date_scan']
        extra_kwargs = {
            'date_scan': {'format': '%Y-%m-%dT%H:%M:%S.%f%z'}
        }