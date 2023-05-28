from django.urls import include, path
from django.conf import settings
from django.contrib import admin
from django_otp.admin import OTPAdminSite
from django.conf.urls.static import static

admin.site.__class__ = OTPAdminSite

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('api.urls')),
    path('blog/', include('blog.urls')),
    path('', include('directory.urls')),
    path('markdownx/', include('markdownx.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL,
                          document_root=settings.MEDIA_ROOT)