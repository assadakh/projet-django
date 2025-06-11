from django.urls import path
from . import views 


urlpatterns = [
    path('nmapscan/', views.nmapscan.as_view()),
    path('whatwebscan/', views.whatwebscan.as_view()),
    path('zapscan/', views.zapscan.as_view()),
]