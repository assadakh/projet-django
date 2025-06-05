from django.urls import path
from . import views 

urlpatterns = [
    path('nmapscan/', views.nmap_scan, name='nmap_scan'),
    path('whatwebscan/', views.whatweb_scan, name="whatweb_scan"),
    path('zapscan/', views.zap_scan, name="zap_scan"),
]