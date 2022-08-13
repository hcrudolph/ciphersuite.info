from django.contrib import admin
from directory.models import *
from markdownx.admin import MarkdownxModelAdmin

admin.site.register(CipherSuite)
admin.site.register(Rfc)
admin.site.register(ProtocolVersion)
admin.site.register(TlsVersion)
admin.site.register(KexAlgorithm)
admin.site.register(AuthAlgorithm)
admin.site.register(EncAlgorithm)
admin.site.register(HashAlgorithm)
admin.site.register(Vulnerability, MarkdownxModelAdmin)
admin.site.register(StaticPage, MarkdownxModelAdmin)
admin.site.register(Announcement)
