from django.urls import path
from . import views 


urlpatterns = [
    path('nmapscan/', views.NmapScanAPIView.as_view(), name='nmap-scan'),
    path('whatwebscan/', views.WhatWebScanAPIView.as_view(), name='whatweb-scan'),
    path('zapscan/', views.ZapScanAPIView.as_view(), name='zap-scan'),
]