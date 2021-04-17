from django.contrib import admin
from directory.models import *

admin.site.register(CipherSuite)
admin.site.register(Rfc)
admin.site.register(ProtocolVersion)
admin.site.register(TlsVersion)
admin.site.register(KexAlgorithm)
admin.site.register(AuthAlgorithm)
admin.site.register(EncAlgorithm)
admin.site.register(HashAlgorithm)
admin.site.register(Vulnerability)
admin.site.register(StaticPage)
admin.site.register(Announcement)
