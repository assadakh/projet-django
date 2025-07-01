from django.urls import path
from . import views
from .views import dashboard, login_view
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    # 🔐 Authentification JWT
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/register/', views.RegisterAPIView.as_view(), name='register'),

    # 🔎 Vues de scans
    path('api/nmapscan/', views.NmapScanAPIView.as_view(), name='api-nmap'),
    path('api/whatwebscan/', views.WhatWebScanAPIView.as_view(), name='api-whatweb'),
    path('api/zapscan/', views.ZapScanAPIView.as_view(), name='api-zap'),
    
    path('dashboard/', dashboard, name='dashboard'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register_page'),
]