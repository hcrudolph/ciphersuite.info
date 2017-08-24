from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.recent_posts, name='recent_posts'),
    url(r'^tags/$', views.tag_archive, name='tag_archive'),
    url(r'^tags/(?P<tag_slug>[a-zA-Z0-9_-]+)/$', views.tag_post_archive, name='tag_post_archive'),
    url(r'^authors/$', views.author_archive, name='author_archive'),
    url(r'^authors/(?P<author_slug>[a-zA-Z0-9_-]+)/$', views.author_post_archive, name='author_post_archive'),
    url(r'^categories/$', views.category_archive, name='category_archive'),
    url(r'^categories/(?P<category_slug>[a-zA-Z0-9_-]+)/$', views.category_post_archive, name='category_post_archive'),
    url(r'^(?P<year>[0-9]{4})/$', views.yearly_post_archive, name='yearly_post_archive'),
    url(r'^(?P<year>[0-9]{4})\/(?P<month>[0-9]{2})/$', views.monthly_post_archive, name='monthly_post_archive'),
    url(r'^(?P<year>[0-9]{4})\/(?P<month>[0-9]{2})\/(?P<day>[0-9]{2})/$', views.daily_post_archive, name='daily_post_archive'),
    url(r'^(?P<year>[0-9]{4})\/(?P<month>[0-9]{2})\/(?P<day>[0-9]{2})\/(?P<post_slug>[a-zA-Z0-9_-]+)/$', views.single_post, name='single_post'),
]
