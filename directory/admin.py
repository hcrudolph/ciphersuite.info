from django.contrib import admin

# Register your models here.

from .models import *

admin.site.register(CipherSuite)
admin.site.register(Rfc)
