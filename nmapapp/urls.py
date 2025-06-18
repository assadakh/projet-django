from django.urls import path
from . import views 
from rest_framework_simplejwt.views import (TokenObtainPairView, TokenRefreshView,)


urlpatterns = [
    # 🔐 Authentification JWT
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),  # Connexion (login)
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),  # Refresh token
    path('api/register/', views.RegisterAPIView.as_view(), name='register'),  # Inscription (signup)

    # 🔎 Vues de scans
    path('nmapscan/', views.NmapScanAPIView.as_view(), name='nmap-scan'),
    path('whatwebscan/', views.WhatWebScanAPIView.as_view(), name='whatweb-scan'),
    path('zapscan/', views.ZapScanAPIView.as_view(), name='zap-scan'),
]