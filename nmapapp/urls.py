from django.urls import path
from . import views 


urlpatterns = [
    path('testjsonnmap/', views.nmapscan.as_view()),
    path('testjsonzap/', views.zapscan.as_view()),
    path('testjsonwhatweb/', views.whatwebscan.as_view()),
    # path('nmapscan/', views.nmap_scan.as_view(), name='nmap_scan'),
    # path('whatwebscan/', views.whatweb_scan.as_view(), name="whatweb_scan"),
    # path('zapscan/', views.zap_scan.as_view(), name="zap_scan"),
]