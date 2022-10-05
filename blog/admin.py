from django.contrib import admin
from .models import *
from markdownx.admin import MarkdownxModelAdmin

admin.site.register(Post, MarkdownxModelAdmin)
admin.site.register(Category)
admin.site.register(Tag)