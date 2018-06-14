from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^cs/$', views.index_cs, name='index_cs'),
    url(r'^rfc/$', views.index_rfc, name='index_rfc'),
    url(r'^search/$', views.search, name='search'),
    url(r'^static/(?P<sp_name>[a-zA-Z0-9_]+)/$', views.static_page, name='static_page'),
    url(r'^cs/(?P<cs_name>[a-zA-Z0-9_]+)/$', views.detail_cs, name='detail_cs'),
    url(r'^rfc/(?P<rfc_number>[0-9]+)/$', views.detail_rfc, name='detail_rfc'),
]
