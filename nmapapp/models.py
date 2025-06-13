from django.db import models

class ScanNmap(models.Model):
    ip = models.GenericIPAddressField()
    port = models.CharField(max_length=20)
    state = models.CharField(max_length=20)
    service = models.CharField(max_length=50)
    date_scan = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip}:{self.port} - {self.service} ({self.state})"


class ScanWhatweb(models.Model):
    url = models.URLField()
    result = models.CharField(max_length=255)
    date_scan = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url
    

class ScanZap(models.Model):
    url = models.URLField()
    alert = models.CharField(max_length=100)
    name = models.CharField(max_length=50)
    risk = models.CharField(max_length=20)
    confidence = models.CharField(max_length=20)
    description = models.TextField()
    solution = models.TextField()
    reference = models.URLField()
    date_scan = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.url} - {self.alert} ({self.risk})"
