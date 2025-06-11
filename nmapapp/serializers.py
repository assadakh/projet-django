from rest_framework import serializers


# Serializer pour Nmap : liste de dicts avec port, state et service
class PortInfoSerializer(serializers.Serializer):
    port = serializers.CharField()
    state = serializers.CharField()
    service = serializers.CharField()


class NmapScanSerializer(serializers.Serializer):
    ip = serializers.IPAddressField()
    result = serializers.ListField(child=PortInfoSerializer())


# Serializer pour WhatWeb : liste de chaînes (des technologies détectées)
class WhatWebResultSerializer(serializers.Serializer):
    url = serializers.URLField()
    result = serializers.ListField(child=serializers.CharField())


# Serializer pour ZAP : liste d’alertes, on les décrit simplement comme des dicts génériques
class ZAPAlertSerializer(serializers.Serializer):
    alert = serializers.CharField()
    name = serializers.CharField(required=False)
    risk = serializers.CharField(required=False)
    confidence = serializers.CharField(required=False)
    description = serializers.CharField(required=False)
    solution = serializers.CharField(required=False)
    reference = serializers.CharField(required=False)

class ZAPResultSerializer(serializers.Serializer):
    url = serializers.URLField()
    result = serializers.ListField(child=serializers.DictField())

