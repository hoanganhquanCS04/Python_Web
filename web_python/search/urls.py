from django.urls import path
from . import views

urlpatterns = [
    path('search/', views.search, name='search'),
    path('search/history/', views.search_history, name='search_history'),

]
