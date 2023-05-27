from django.urls import path, re_path, include
from . import views

urlpatterns = [
    path('', views.recent_posts),
    path('tags/', views.tag_archive),
    re_path(r'^tags/(?P<tag_slug>[a-zA-Z0-9_-]+)/$', views.tag_post_archive),
    path('authors/', views.author_archive),
    re_path(r'^authors/(?P<author_slug>[a-zA-Z0-9_-]+)/$', views.author_post_archive),
    path('categories/', views.category_archive),
    path('markdownx/', include('markdownx.urls')),
    re_path(r'^categories/(?P<category_slug>[a-zA-Z0-9_-]+)/$', views.category_post_archive),
    re_path(r'^(?P<year>[0-9]{4})/$', views.yearly_post_archive),
    re_path(r'^(?P<year>[0-9]{4})\/(?P<month>[0-9]{2})/$', views.monthly_post_archive),
    re_path(r'^(?P<year>[0-9]{4})\/(?P<month>[0-9]{2})\/(?P<day>[0-9]{2})/$', views.daily_post_archive),
    re_path(r'^(?P<year>[0-9]{4})\/(?P<month>[0-9]{2})\/(?P<day>[0-9]{2})\/(?P<post_slug>[a-zA-Z0-9_-]+)/$', views.single_post),
]