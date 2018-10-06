from django.urls import path, re_path
import api.views as views 

urlpatterns = [
    path('', views.api_root),
    path('cs/', views.cs_all),
    path('cs/security/<sec_level>/', views.cs_by_security),
    path('cs/software/<software>/', views.cs_by_software),
    path('cs/tls/<tlsv>/', views.cs_by_tlsversion),
    path('rfc/', views.rfc_all),
    re_path(r'^cs/(?P<iana_name>[a-zA-Z0-9_]+)/$', views.cs_single),
    re_path(r'^rfc/(?P<rfc_number>[0-9]+)/$', views.rfc_single),
]