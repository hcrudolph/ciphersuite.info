from django.urls import path, re_path
import directory.views as views

urlpatterns = [
    path('', views.index),
    path('cs/', views.index_cs),
    path('rfc/', views.index_rfc),
    path('search/', views.search),
    re_path(r'^page/(?P<sp_name>[a-zA-Z0-9_]+)/$', views.static_page),
    re_path(r'^cs/(?P<cs_name>[a-zA-Z0-9_]+)/$', views.detail_cs, name='detail_cs'),
    re_path(r'^rfc/(?P<rfc_number>[0-9]+)/$', views.detail_rfc, name='detail_rfc'),
]