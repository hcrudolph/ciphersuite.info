from django.contrib import admin
from .models import *

admin.site.register(Post)
admin.site.register(Category)
admin.site.register(Tag)