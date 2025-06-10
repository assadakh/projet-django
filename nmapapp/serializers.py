from rest_framework import serializers


# Serializer nmap
class NmapScanSerializer(serializers.Serializer):
    ip = serializers.IPAddressField()
    result = serializers.ListField(child=serializers.CharField())


# Serializer WhatWeb
class WhatWebResultSerializer(serializers.Serializer):
    url = serializers.URLField()
    result = serializers.ListField(child=serializers.CharField())


# Serializer ZAP
class ZapScanSerializer(serializers.Serializer):
    url = serializers.URLField()
    result = serializers.ListField(child=serializers.CharField())
