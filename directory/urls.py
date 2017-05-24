from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index_global, name='index_global'),
    url(r'^cs/$', views.index_cs, name='index_cs'),
    url(r'^rfc/$', views.index_rfc, name='index_rfc'),
    url(r'^about/$', views.about, name='about'),
    url(r'^search/$', views.search, name='search'),
    url(r'^cs/(?P<cs_name>[a-zA-Z0-9_]+)/$', views.detail_cs, name='detail_cs'),
    url(r'^rfc/(?P<rfc_number>[0-9]+)/$', views.detail_rfc, name='detail_rfc'),
]
