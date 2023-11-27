from django.urls import path, re_path
import api.views as views

urlpatterns = [
    path('', views.api_root),
    path('cs/', views.cs_all),
    path('cs/security/<sec_level>/', views.cs_by_security),
    path('cs/software/<software>/', views.cs_by_software),
    path('cs/tls/<tlsv>/', views.cs_by_tlsversion),
    path('rfc/', views.rfc_all),
    path('cs/<iana_name>/', views.cs_single),
    re_path(r'^rfc/(?P<rfc_number>[0-9]+)/$', views.rfc_single),

    path('v2/', views.api_root_v2),
    path('v2/cs/', views.cs_all_v2),
    path('v2/cs/<algo_type>/<search_term>/', views.search_cs_by_algorithm_v2),
    path('v2/cs/security/<sec_level>/', views.cs_by_security_v2),
    path('v2/cs/software/<software>/', views.cs_by_software_v2),
    path('v2/cs/tls/<tls_version>/', views.cs_by_tlsversion_v2),
    path('v2/cs/<iana_name>/', views.cs_single_v2),

    path('v2/algo/', views.algo_all_v2),
    path('v2/algo/type/<algo_type>/', views.algo_by_type_v2),
    path('v2/algo/sev/<severity>/', views.algo_by_severity_v2),

    path('v2/vuln/', views.vuln_all_v2),
    path('v2/vuln/<vuln_name>/', views.vuln_by_name_v2),
    path('v2/vuln/sev/<severity>/', views.vuln_by_severity_v2),
    path('v2/vuln/cs/<iana_name>/', views.vuln_by_csname_v2),

    path('v2/rfc/', views.rfc_all_v2),
    re_path(r'^v2/rfc/(?P<rfc_number>[0-9]+)/$', views.rfc_single_v2),
]